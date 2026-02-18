import hashlib
import json
import logging
import re
import requests

from django.db.models import Sum
from django import http
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, render
from django.template.loader import get_template
from django.utils import timezone
from weasyprint import HTML

from dashboard.models import (
	OTXAlienVaultAPIKey,
	LeakCheckAPIKey,
	Project,
)
from targetApp.models import Domain
from threatIntel.models import (
	OTXThreatData,
	LeakCheckData,
	ThreatIntelScanStatus,
	ManualIndicator,
	ThreatIntelReportSetting,
)

logger = logging.getLogger(__name__)

OTX_BASE_URL = 'https://otx.alienvault.com/api/v1'
LEAKCHECK_BASE_URL = 'https://leakcheck.io/api/v2/query'


# ──────────────────────────────────────
# OTX helpers
# ──────────────────────────────────────

def _fetch_otx_pulses(api_key, limit=20):
	"""Fetch latest subscribed pulses from OTX (global threat feed)."""
	headers = {'X-OTX-API-KEY': api_key}
	try:
		resp = requests.get(
			f'{OTX_BASE_URL}/pulses/subscribed',
			headers=headers,
			params={'limit': limit, 'page': 1},
			timeout=30,
		)
		if resp.status_code == 200:
			data = resp.json()
			return [
				{
					'id': p.get('id', ''),
					'name': p.get('name', ''),
					'description': (p.get('description', '') or '')[:300],
					'created': p.get('created', ''),
					'modified': p.get('modified', ''),
					'tags': p.get('tags', [])[:10],
					'adversary': p.get('adversary', ''),
					'targeted_countries': p.get('targeted_countries', []),
					'malware_families': [
						m.get('display_name', '') if isinstance(m, dict) else str(m)
						for m in (p.get('malware_families', []) or [])
					],
					'attack_ids': [
						a.get('display_name', '') if isinstance(a, dict) else str(a)
						for a in (p.get('attack_ids', []) or [])
					],
					'indicator_count': len(p.get('indicators', [])),
					'indicators': [
						{
							'type': ind.get('type', ''),
							'indicator': ind.get('indicator', ''),
							'title': ind.get('title', ''),
						}
						for ind in (p.get('indicators', []) or [])[:50]
					],
				}
				for p in data.get('results', [])
			]
	except requests.RequestException as e:
		logger.error(f'OTX subscribed pulses error: {e}')
	return []


def _fetch_otx_data(domain_name, api_key):
	"""Fetch threat data from OTX AlienVault for a specific domain."""
	headers = {'X-OTX-API-KEY': api_key}
	base = f'{OTX_BASE_URL}/indicators/domain'
	result = {
		'pulse_count': 0,
		'reputation': 0,
		'pulses': [],
		'malware_samples': [],
		'passive_dns': [],
		'analyzed_urls': [],
		'malware_count': 0,
		'passive_dns_count': 0,
		'url_count': 0,
		'whois_data': {},
	}
	try:
		# General info (pulses + reputation)
		resp = requests.get(f'{base}/{domain_name}/general', headers=headers, timeout=30)
		if resp.status_code == 200:
			data = resp.json()
			result['pulse_count'] = data.get('pulse_info', {}).get('count', 0)
			result['reputation'] = data.get('reputation', 0)
			pulses = data.get('pulse_info', {}).get('pulses', [])
			result['pulses'] = [
				{
					'id': p.get('id', ''),
					'name': p.get('name', ''),
					'description': (p.get('description', '') or '')[:200],
					'created': p.get('created', ''),
					'tags': p.get('tags', [])[:10],
					'adversary': p.get('adversary', ''),
					'indicators': [
						{
							'type': ind.get('type', ''),
							'indicator': ind.get('indicator', ''),
							'title': ind.get('title', ''),
						}
						for ind in (p.get('indicators', []) or [])[:50]
					],
				}
				for p in pulses[:50]
			]
			result['whois_data'] = data.get('whois', {}) or {}

		# Malware samples
		resp = requests.get(f'{base}/{domain_name}/malware', headers=headers, timeout=30)
		if resp.status_code == 200:
			data = resp.json()
			samples = data.get('data', [])
			result['malware_count'] = len(samples)
			result['malware_samples'] = [
				{
					'hash': s.get('hash', ''),
					'detections': s.get('detections', {}),
					'date': s.get('datetime_int', ''),
				}
				for s in samples[:50]
			]

		# Passive DNS
		resp = requests.get(f'{base}/{domain_name}/passive_dns', headers=headers, timeout=30)
		if resp.status_code == 200:
			data = resp.json()
			dns_records = data.get('passive_dns', [])
			result['passive_dns_count'] = len(dns_records)
			result['passive_dns'] = [
				{
					'hostname': r.get('hostname', ''),
					'address': r.get('address', ''),
					'record_type': r.get('record_type', ''),
					'first': r.get('first', ''),
					'last': r.get('last', ''),
				}
				for r in dns_records[:100]
			]

		# URL list
		resp = requests.get(f'{base}/{domain_name}/url_list', headers=headers, timeout=30)
		if resp.status_code == 200:
			data = resp.json()
			urls = data.get('url_list', [])
			result['url_count'] = len(urls)
			result['analyzed_urls'] = [
				{
					'url': u.get('url', ''),
					'date': u.get('date', ''),
					'httpcode': u.get('httpcode', 0),
				}
				for u in urls[:100]
			]

	except requests.RequestException as e:
		raise Exception(f'OTX API error: {str(e)}')

	return result


def _fetch_otx_indicator(indicator_value, indicator_type, api_key):
	"""Fetch OTX data for a manual indicator (domain, IPv4, hostname)."""
	headers = {'X-OTX-API-KEY': api_key}
	# Map indicator types to OTX API section
	type_map = {
		'domain': 'domain',
		'subdomain': 'hostname',
		'ip': 'IPv4',
	}
	section = type_map.get(indicator_type, 'domain')
	url = f'{OTX_BASE_URL}/indicators/{section}/{indicator_value}/general'
	result = {'pulse_count': 0, 'pulses': [], 'reputation': 0}
	try:
		resp = requests.get(url, headers=headers, timeout=30)
		if resp.status_code == 200:
			data = resp.json()
			result['pulse_count'] = data.get('pulse_info', {}).get('count', 0)
			result['reputation'] = data.get('reputation', 0)
			pulses = data.get('pulse_info', {}).get('pulses', [])
			result['pulses'] = [
				{
					'id': p.get('id', ''),
					'name': p.get('name', ''),
					'description': (p.get('description', '') or '')[:200],
					'created': p.get('created', ''),
					'tags': p.get('tags', [])[:10],
					'adversary': p.get('adversary', ''),
				}
				for p in pulses[:30]
			]
	except requests.RequestException as e:
		raise Exception(f'OTX indicator lookup error: {str(e)}')
	return result


# ──────────────────────────────────────
# LeakCheck helpers
# ──────────────────────────────────────

def _fetch_leakcheck_data(domain_name, api_key):
	"""Fetch leak data from LeakCheck for a domain.
	Uses two search types: domain (email leaks) and origin (stealer log leaks).
	API v2 docs: https://wiki.leakcheck.io/en/api/api-v2-pro
	"""
	headers = {
		'X-API-Key': api_key,
		'Accept': 'application/json',
	}
	all_entries = []

	for search_type in ('domain', 'origin'):
		try:
			resp = requests.get(
				f'{LEAKCHECK_BASE_URL}/{domain_name}',
				params={'type': search_type, 'limit': 1000},
				headers=headers,
				timeout=30,
			)
			if resp.status_code == 200:
				data = resp.json()
				if data.get('success'):
					entries = data.get('result', [])
					for e in entries:
						source = e.get('source', {}) or {}
						all_entries.append({
							'email': e.get('email', ''),
							'username': e.get('username', ''),
							'password': e.get('password', ''),
							'origin': e.get('origin', ''),
							'source_name': source.get('name', ''),
							'breach_date': source.get('breach_date', ''),
							'search_type': search_type,
							'fields': e.get('fields', []),
						})
			elif resp.status_code == 401:
				raise Exception('LeakCheck API: Invalid API key')
			elif resp.status_code == 403:
				logger.warning(f'LeakCheck {search_type} query for {domain_name}: 403 (skipped)')
				continue
		except requests.RequestException as e:
			logger.error(f'LeakCheck API error ({search_type}) for {domain_name}: {e}')
			continue

	return {
		'total_found': len(all_entries),
		'leaked_credentials': all_entries[:500],
	}


def _credential_hash(cred):
	"""Generate a unique hash for a credential entry for checked tracking."""
	key = f"{cred.get('email','')}{cred.get('username','')}{cred.get('password','')}{cred.get('source_name','')}"
	return hashlib.md5(key.encode()).hexdigest()


# ──────────────────────────────────────
# Views
# ──────────────────────────────────────

def index(request, slug):
	"""Main Threat Intelligence page."""
	project = get_object_or_404(Project, slug=slug)
	domains = Domain.objects.filter(project=project)

	otx_key = OTXAlienVaultAPIKey.objects.first()
	leakcheck_key = LeakCheckAPIKey.objects.first()
	has_api_keys = bool(otx_key or leakcheck_key)

	# Get cached data
	otx_data = OTXThreatData.objects.filter(project=project)
	leak_data = LeakCheckData.objects.filter(project=project)

	# Summary stats
	total_pulses = otx_data.aggregate(total=Sum('pulse_count'))['total'] or 0
	total_malware = otx_data.aggregate(total=Sum('malware_count'))['total'] or 0
	total_leaks = leak_data.aggregate(total=Sum('total_found'))['total'] or 0
	domains_with_threats = otx_data.filter(pulse_count__gt=0).count()
	domains_with_leaks = leak_data.filter(total_found__gt=0).count()

	# Risk score — weighted by direct relevance to domain owner
	# Component 1: OTX Reputation (0-25) — direct domain assessment
	max_reputation = 0
	for od in otx_data:
		if od.reputation and od.reputation > max_reputation:
			max_reputation = od.reputation
	reputation_score = min(25, max_reputation * 5)

	# Component 2: Credential Exposure (0-35) — leaked credentials per domain
	total_domains = domains.count() or 1
	leaks_per_domain = total_leaks / total_domains
	if leaks_per_domain >= 50:
		leak_score = 35
	elif leaks_per_domain >= 20:
		leak_score = 25
	elif leaks_per_domain >= 10:
		leak_score = 18
	elif leaks_per_domain >= 5:
		leak_score = 12
	elif total_leaks > 0:
		leak_score = 5
	else:
		leak_score = 0

	# Component 3: Malware Association (0-10) — feed-based, not actual malware in env
	malware_score = min(10, total_malware * 2)

	# Component 4: Threat Exposure (0-30) — ratio of domains in threat feeds
	if total_domains > 0:
		exposure_ratio = domains_with_threats / total_domains
		exposure_score = min(30, round(exposure_ratio * 30))
	else:
		exposure_score = 0

	risk_score = min(100, reputation_score + leak_score + malware_score + exposure_score)

	# Build OTX threat table
	threat_table = []
	for domain in domains:
		otx = otx_data.filter(domain=domain).first()
		threat_table.append({
			'id': domain.id,
			'name': domain.name,
			'pulse_count': otx.pulse_count if otx else '-',
			'malware_count': otx.malware_count if otx else '-',
			'passive_dns_count': otx.passive_dns_count if otx else '-',
			'url_count': otx.url_count if otx else '-',
			'last_checked': otx.fetched_at if otx else None,
			'has_data': bool(otx),
			'fetch_error': otx.fetch_error if otx else None,
		})

	# Build LeakCheck table
	leak_table = []
	for domain in domains:
		leak = leak_data.filter(domain=domain).first()
		leak_table.append({
			'id': domain.id,
			'name': domain.name,
			'total_found': leak.total_found if leak else '-',
			'last_checked': leak.fetched_at if leak else None,
			'has_data': bool(leak),
			'fetch_error': leak.fetch_error if leak else None,
		})

	# Scan status
	scan_status = ThreatIntelScanStatus.objects.filter(project=project).first()

	# Fetch latest OTX pulses feed (global, not per-domain)
	latest_pulses = []
	if otx_key:
		latest_pulses = _fetch_otx_pulses(otx_key.key, limit=10)

	# Manual indicators
	manual_indicators = ManualIndicator.objects.filter(project=project).order_by('-created_at')

	# Extract IoCs and CVEs from stored pulses
	all_pulses = []
	for od in otx_data:
		for p in (od.pulses or []):
			all_pulses.append(p)
	for mi in manual_indicators:
		for p in (mi.otx_data.get('pulses', []) if mi.otx_data else []):
			all_pulses.append(p)
	all_pulses.extend(latest_pulses)

	iocs = _extract_iocs(all_pulses)
	cves = _extract_cves(all_pulses)

	# IoC type counts for chart
	ioc_type_counts = {t: len(v) for t, v in iocs.items()}

	# Flatten IoC list for table (top 100)
	ioc_flat = []
	for ioc_type, indicators in iocs.items():
		for ind in indicators[:30]:
			ioc_flat.append({
				'type': ioc_type,
				'value': ind['value'],
				'pulse': ind['pulse'],
			})

	# Leak per domain for chart
	leak_per_domain = []
	for ld in leak_data:
		if ld.total_found > 0:
			leak_per_domain.append({
				'domain': ld.domain.name,
				'count': ld.total_found,
			})
	leak_per_domain.sort(key=lambda x: x['count'], reverse=True)

	# CVE per pulse for chart
	cve_pulse_counts = {}
	for cve in cves:
		pulse_name = cve.get('pulse', 'Unknown')[:40]
		cve_pulse_counts[pulse_name] = cve_pulse_counts.get(pulse_name, 0) + 1
	cve_per_pulse = [{'pulse': k, 'count': v} for k, v in cve_pulse_counts.items()]
	cve_per_pulse.sort(key=lambda x: x['count'], reverse=True)

	context = {
		'threat_intel_active': 'active',
		'project': project,
		'has_api_keys': has_api_keys,
		'has_otx_key': bool(otx_key),
		'has_leakcheck_key': bool(leakcheck_key),
		'total_pulses': total_pulses,
		'total_malware': total_malware,
		'total_leaks': total_leaks,
		'domains_with_threats': domains_with_threats,
		'domains_with_leaks': domains_with_leaks,
		'risk_score': risk_score,
		'threat_table': threat_table,
		'leak_table': leak_table,
		'latest_pulses': latest_pulses,
		'scan_status': scan_status,
		'manual_indicators': manual_indicators,
		'ioc_flat': ioc_flat[:100],
		'ioc_type_counts': ioc_type_counts,
		'cves': cves[:50],
		'leak_per_domain': leak_per_domain[:10],
		'cve_per_pulse': cve_per_pulse[:10],
	}
	return render(request, 'threatIntel/index.html', context)


def refresh_all(request, slug):
	"""Refresh threat intel data for all domains in the project."""
	if request.method != 'POST':
		return http.JsonResponse({'status': False, 'error': 'POST required'}, status=405)

	project = get_object_or_404(Project, slug=slug)
	domains = Domain.objects.filter(project=project)

	otx_key_obj = OTXAlienVaultAPIKey.objects.first()
	leakcheck_key_obj = LeakCheckAPIKey.objects.first()

	if not otx_key_obj and not leakcheck_key_obj:
		return http.JsonResponse({
			'status': False,
			'error': 'No API keys configured. Please add keys in Settings > API Vault.',
		})

	otx_key = otx_key_obj.key if otx_key_obj else None
	leakcheck_key = leakcheck_key_obj.key if leakcheck_key_obj else None

	# Initialize scan status
	scan_status, _ = ThreatIntelScanStatus.objects.get_or_create(project=project)
	scan_status.is_scanning = True
	scan_status.domains_scanned = 0
	scan_status.domains_total = domains.count()
	scan_status.save()

	errors = []
	for i, domain in enumerate(domains):
		# Fetch OTX data
		if otx_key:
			try:
				otx_result = _fetch_otx_data(domain.name, otx_key)
				OTXThreatData.objects.update_or_create(
					domain=domain, project=project,
					defaults=otx_result,
				)
			except Exception as e:
				logger.error(f'OTX fetch error for {domain.name}: {e}')
				OTXThreatData.objects.update_or_create(
					domain=domain, project=project,
					defaults={'fetch_error': str(e)},
				)
				errors.append(f'OTX error for {domain.name}: {str(e)}')

		# Fetch LeakCheck data
		if leakcheck_key:
			try:
				leak_result = _fetch_leakcheck_data(domain.name, leakcheck_key)
				LeakCheckData.objects.update_or_create(
					domain=domain, project=project,
					defaults=leak_result,
				)
			except Exception as e:
				logger.error(f'LeakCheck fetch error for {domain.name}: {e}')
				LeakCheckData.objects.update_or_create(
					domain=domain, project=project,
					defaults={'fetch_error': str(e)},
				)
				errors.append(f'LeakCheck error for {domain.name}: {str(e)}')

		# Update progress
		scan_status.domains_scanned = i + 1
		scan_status.save()

	# Mark scan as complete
	scan_status.is_scanning = False
	scan_status.last_scan_at = timezone.now()
	scan_status.save()

	return http.JsonResponse({
		'status': True,
		'domains_scanned': scan_status.domains_scanned,
		'errors': errors,
	})


def refresh_domain(request, slug, id):
	"""Refresh threat intel data for a single domain."""
	if request.method != 'POST':
		return http.JsonResponse({'status': False, 'error': 'POST required'}, status=405)

	project = get_object_or_404(Project, slug=slug)
	domain = get_object_or_404(Domain, id=id, project=project)

	otx_key_obj = OTXAlienVaultAPIKey.objects.first()
	leakcheck_key_obj = LeakCheckAPIKey.objects.first()

	if not otx_key_obj and not leakcheck_key_obj:
		return http.JsonResponse({'status': False, 'error': 'No API keys configured.'})

	otx_key = otx_key_obj.key if otx_key_obj else None
	leakcheck_key = leakcheck_key_obj.key if leakcheck_key_obj else None
	errors = []

	if otx_key:
		try:
			otx_result = _fetch_otx_data(domain.name, otx_key)
			OTXThreatData.objects.update_or_create(
				domain=domain, project=project, defaults=otx_result,
			)
		except Exception as e:
			errors.append(f'OTX: {str(e)}')
			OTXThreatData.objects.update_or_create(
				domain=domain, project=project, defaults={'fetch_error': str(e)},
			)

	if leakcheck_key:
		try:
			leak_result = _fetch_leakcheck_data(domain.name, leakcheck_key)
			LeakCheckData.objects.update_or_create(
				domain=domain, project=project, defaults=leak_result,
			)
		except Exception as e:
			errors.append(f'LeakCheck: {str(e)}')
			LeakCheckData.objects.update_or_create(
				domain=domain, project=project, defaults={'fetch_error': str(e)},
			)

	return http.JsonResponse({
		'status': len(errors) == 0,
		'errors': errors,
	})


def scan_status(request, slug):
	"""Return scan progress as JSON for polling."""
	project = get_object_or_404(Project, slug=slug)
	status = ThreatIntelScanStatus.objects.filter(project=project).first()
	if not status:
		return http.JsonResponse({
			'is_scanning': False,
			'domains_scanned': 0,
			'domains_total': 0,
			'last_scan_at': None,
		})
	return http.JsonResponse({
		'is_scanning': status.is_scanning,
		'domains_scanned': status.domains_scanned,
		'domains_total': status.domains_total,
		'last_scan_at': status.last_scan_at.isoformat() if status.last_scan_at else None,
	})


def domain_detail(request, slug, id):
	"""Return full threat intel detail for a domain as JSON (for modal)."""
	project = get_object_or_404(Project, slug=slug)
	domain = get_object_or_404(Domain, id=id, project=project)

	otx = OTXThreatData.objects.filter(domain=domain, project=project).first()
	leak = LeakCheckData.objects.filter(domain=domain, project=project).first()

	result = {
		'domain': domain.name,
		'otx': None,
		'leakcheck': None,
	}

	if otx:
		result['otx'] = {
			'pulse_count': otx.pulse_count,
			'reputation': otx.reputation,
			'pulses': otx.pulses,
			'malware_samples': otx.malware_samples,
			'malware_count': otx.malware_count,
			'passive_dns': otx.passive_dns,
			'passive_dns_count': otx.passive_dns_count,
			'analyzed_urls': otx.analyzed_urls,
			'url_count': otx.url_count,
			'whois_data': otx.whois_data,
			'fetched_at': otx.fetched_at.isoformat(),
			'fetch_error': otx.fetch_error,
		}

	if leak:
		checked = set(leak.checked_credentials or [])
		creds_with_status = []
		# Build source summary: group by source_name + search_type
		source_map = {}  # source_name -> {type, count, sample_emails}
		for c in leak.leaked_credentials:
			h = _credential_hash(c)
			creds_with_status.append({
				**c,
				'hash': h,
				'checked': h in checked,
			})
			src = c.get('source_name', 'Unknown') or 'Unknown'
			stype = c.get('search_type', 'domain')
			key = f'{src}|{stype}'
			if key not in source_map:
				source_map[key] = {
					'source_name': src,
					'search_type': stype,
					'count': 0,
					'sample_emails': [],
				}
			source_map[key]['count'] += 1
			email = c.get('email', '')
			if email and len(source_map[key]['sample_emails']) < 3:
				if email not in source_map[key]['sample_emails']:
					source_map[key]['sample_emails'].append(email)

		source_summary = sorted(source_map.values(), key=lambda x: x['count'], reverse=True)

		result['leakcheck'] = {
			'id': leak.id,
			'total_found': leak.total_found,
			'leaked_credentials': creds_with_status,
			'source_summary': source_summary,
			'fetched_at': leak.fetched_at.isoformat(),
			'fetch_error': leak.fetch_error,
		}

	return http.JsonResponse(result)


def toggle_checked_credential(request, slug, id):
	"""Toggle the checked status of a credential entry."""
	if request.method != 'POST':
		return http.JsonResponse({'status': False, 'error': 'POST required'}, status=405)

	project = get_object_or_404(Project, slug=slug)
	leak = get_object_or_404(LeakCheckData, id=id, project=project)

	try:
		body = json.loads(request.body)
	except (json.JSONDecodeError, ValueError):
		return http.JsonResponse({'status': False, 'error': 'Invalid JSON'}, status=400)

	cred_hash = body.get('hash', '')
	checked = body.get('checked', True)

	checked_set = set(leak.checked_credentials or [])
	if checked:
		checked_set.add(cred_hash)
	else:
		checked_set.discard(cred_hash)

	leak.checked_credentials = list(checked_set)
	leak.save(update_fields=['checked_credentials'])

	return http.JsonResponse({'status': True, 'checked': checked})


# ──────────────────────────────────────
# Manual Indicators
# ──────────────────────────────────────

def add_indicator(request, slug):
	"""Add a manual indicator (domain/subdomain/IP) for OTX pulse checking."""
	if request.method != 'POST':
		return http.JsonResponse({'status': False, 'error': 'POST required'}, status=405)

	project = get_object_or_404(Project, slug=slug)

	try:
		body = json.loads(request.body)
	except (json.JSONDecodeError, ValueError):
		return http.JsonResponse({'status': False, 'error': 'Invalid JSON'}, status=400)

	indicator_type = body.get('indicator_type', '').strip()
	value = body.get('value', '').strip()

	if indicator_type not in ('domain', 'subdomain', 'ip'):
		return http.JsonResponse({'status': False, 'error': 'Invalid indicator type'}, status=400)
	if not value:
		return http.JsonResponse({'status': False, 'error': 'Value is required'}, status=400)

	# Check for duplicate
	if ManualIndicator.objects.filter(project=project, indicator_type=indicator_type, value=value).exists():
		return http.JsonResponse({'status': False, 'error': 'Indicator already exists'}, status=409)

	indicator = ManualIndicator.objects.create(
		project=project,
		indicator_type=indicator_type,
		value=value,
	)

	# Auto-fetch OTX data if key available
	otx_key_obj = OTXAlienVaultAPIKey.objects.first()
	if otx_key_obj:
		try:
			otx_result = _fetch_otx_indicator(value, indicator_type, otx_key_obj.key)
			indicator.otx_data = otx_result
			indicator.pulse_count = otx_result.get('pulse_count', 0)
			indicator.fetched_at = timezone.now()
			indicator.save()
		except Exception as e:
			indicator.fetch_error = str(e)
			indicator.save()

	return http.JsonResponse({
		'status': True,
		'indicator': {
			'id': indicator.id,
			'type': indicator.indicator_type,
			'value': indicator.value,
			'pulse_count': indicator.pulse_count,
			'fetched_at': indicator.fetched_at.isoformat() if indicator.fetched_at else None,
		},
	})


def delete_indicator(request, slug, id):
	"""Delete a manual indicator."""
	if request.method != 'POST':
		return http.JsonResponse({'status': False, 'error': 'POST required'}, status=405)

	project = get_object_or_404(Project, slug=slug)
	indicator = get_object_or_404(ManualIndicator, id=id, project=project)
	indicator.delete()
	return http.JsonResponse({'status': True})


def refresh_indicator(request, slug, id):
	"""Refresh OTX data for a manual indicator."""
	if request.method != 'POST':
		return http.JsonResponse({'status': False, 'error': 'POST required'}, status=405)

	project = get_object_or_404(Project, slug=slug)
	indicator = get_object_or_404(ManualIndicator, id=id, project=project)

	otx_key_obj = OTXAlienVaultAPIKey.objects.first()
	if not otx_key_obj:
		return http.JsonResponse({'status': False, 'error': 'No OTX API key configured.'})

	try:
		otx_result = _fetch_otx_indicator(indicator.value, indicator.indicator_type, otx_key_obj.key)
		indicator.otx_data = otx_result
		indicator.pulse_count = otx_result.get('pulse_count', 0)
		indicator.fetched_at = timezone.now()
		indicator.fetch_error = None
		indicator.save()
	except Exception as e:
		indicator.fetch_error = str(e)
		indicator.save()
		return http.JsonResponse({'status': False, 'error': str(e)})

	return http.JsonResponse({
		'status': True,
		'pulse_count': indicator.pulse_count,
	})


def indicator_detail(request, slug, id):
	"""Return full OTX detail for a manual indicator as JSON."""
	project = get_object_or_404(Project, slug=slug)
	indicator = get_object_or_404(ManualIndicator, id=id, project=project)

	return http.JsonResponse({
		'id': indicator.id,
		'type': indicator.indicator_type,
		'value': indicator.value,
		'pulse_count': indicator.pulse_count,
		'otx_data': indicator.otx_data,
		'fetched_at': indicator.fetched_at.isoformat() if indicator.fetched_at else None,
		'fetch_error': indicator.fetch_error,
	})


# ──────────────────────────────────────
# Report Generation
# ──────────────────────────────────────

def _get_banking_keywords(settings):
	"""Get list of banking keywords from settings."""
	if settings and settings.banking_keywords:
		return [k.strip().lower() for k in settings.banking_keywords.split(',') if k.strip()]
	return ['bank', 'banking', 'financial', 'swift', 'payment', 'atm', 'malware', 'trojan', 'phishing', 'credential', 'fraud']


def _filter_banking_pulses(pulses, keywords):
	"""Filter pulses that match banking/financial keywords."""
	matched = []
	for p in pulses:
		text = f"{p.get('name', '')} {p.get('description', '')} {' '.join(p.get('tags', []))}".lower()
		if any(kw in text for kw in keywords):
			matched.append(p)
	return matched


def _extract_iocs(pulses):
	"""Extract IoC indicators from pulses, grouped by type."""
	iocs = {}
	for p in pulses:
		for ind in (p.get('indicators', []) or []):
			ioc_type = ind.get('type', 'unknown')
			if ioc_type not in iocs:
				iocs[ioc_type] = []
			iocs[ioc_type].append({
				'value': ind.get('indicator', ''),
				'title': ind.get('title', ''),
				'pulse': p.get('name', ''),
			})
	return iocs


def _extract_cves(pulses):
	"""Extract CVE mentions from pulses."""
	cve_set = set()
	cves = []
	for p in pulses:
		text = f"{p.get('name', '')} {p.get('description', '')} {' '.join(p.get('tags', []))}"
		found = re.findall(r'CVE-\d{4}-\d{4,}', text, re.IGNORECASE)
		for cve in found:
			cve_upper = cve.upper()
			if cve_upper not in cve_set:
				cve_set.add(cve_upper)
				cves.append({
					'id': cve_upper,
					'pulse': p.get('name', ''),
				})
	return cves


def _calculate_severity_scores(otx_data_list, leak_data_list, banking_pulses, cves):
	"""Calculate severity scores based on findings."""
	scores = []

	# Banking pulse threats
	if banking_pulses:
		count = len(banking_pulses)
		severity = 'CRITICAL' if count >= 5 else 'HIGH' if count >= 2 else 'MEDIUM'
		scores.append({
			'category': 'Financial Threat Pulses',
			'finding': f'{count} financial/banking threat pulse(s) detected',
			'severity': severity,
			'score': min(10, count * 2),
		})

	# CVE findings
	if cves:
		count = len(cves)
		severity = 'HIGH' if count >= 3 else 'MEDIUM' if count >= 1 else 'LOW'
		scores.append({
			'category': 'CVE Vulnerabilities',
			'finding': f'{count} CVE(s) referenced in threat pulses',
			'severity': severity,
			'score': min(10, count * 2),
		})

	# Leaked credentials
	total_leaks = sum(ld.total_found for ld in leak_data_list)
	if total_leaks > 0:
		severity = 'CRITICAL' if total_leaks >= 50 else 'HIGH' if total_leaks >= 10 else 'MEDIUM'
		scores.append({
			'category': 'Credential Exposure',
			'finding': f'{total_leaks} leaked credential(s) found',
			'severity': severity,
			'score': min(10, total_leaks),
		})

	# Malware
	total_malware = sum(od.malware_count for od in otx_data_list)
	if total_malware > 0:
		severity = 'CRITICAL' if total_malware >= 5 else 'HIGH' if total_malware >= 1 else 'MEDIUM'
		scores.append({
			'category': 'Malware Association',
			'finding': f'{total_malware} malware sample(s) associated',
			'severity': severity,
			'score': min(10, total_malware * 3),
		})

	# Domain reputation
	for od in otx_data_list:
		if od.reputation and od.reputation > 0:
			scores.append({
				'category': 'Domain Reputation',
				'finding': f'{od.domain.name} has OTX reputation score {od.reputation}',
				'severity': 'HIGH' if od.reputation >= 5 else 'MEDIUM',
				'score': min(10, od.reputation),
			})

	return scores


def generate_threat_report(request, slug):
	"""Generate Threat Intelligence Report (Banking) as PDF."""
	project = get_object_or_404(Project, slug=slug)

	# Get report settings
	report_settings = ThreatIntelReportSetting.objects.first()
	primary_color = report_settings.primary_color if report_settings else '#1A237E'
	secondary_color = report_settings.secondary_color if report_settings else '#0D1B2A'

	# Get all data
	otx_data_list = list(OTXThreatData.objects.filter(project=project))
	leak_data_list = list(LeakCheckData.objects.filter(project=project))
	manual_indicators = list(ManualIndicator.objects.filter(project=project))

	# Collect all pulses (from domain OTX + manual indicators)
	all_pulses = []
	for od in otx_data_list:
		for p in (od.pulses or []):
			all_pulses.append(p)
	for mi in manual_indicators:
		for p in (mi.otx_data.get('pulses', []) if mi.otx_data else []):
			all_pulses.append(p)

	# Also fetch latest subscribed pulses for banking filter
	otx_key_obj = OTXAlienVaultAPIKey.objects.first()
	subscribed_pulses = []
	if otx_key_obj:
		subscribed_pulses = _fetch_otx_pulses(otx_key_obj.key, limit=50)
		all_pulses.extend(subscribed_pulses)

	# Banking keyword filter
	banking_keywords = _get_banking_keywords(report_settings)
	banking_pulses = _filter_banking_pulses(all_pulses, banking_keywords)

	# Extract IoCs and CVEs
	iocs = _extract_iocs(all_pulses)
	cves = _extract_cves(all_pulses)

	# Severity scoring
	severity_scores = _calculate_severity_scores(otx_data_list, leak_data_list, banking_pulses, cves)
	overall_risk = min(100, sum(s['score'] for s in severity_scores) * 3)

	# Build leak summary (exclude checked credentials)
	all_leaked_creds = []
	for ld in leak_data_list:
		checked_set = set(ld.checked_credentials or [])
		for c in (ld.leaked_credentials or []):
			if _credential_hash(c) in checked_set:
				continue
			c['domain'] = ld.domain.name
			all_leaked_creds.append(c)

	# Summary stats
	total_pulses = sum(od.pulse_count for od in otx_data_list)
	total_malware = sum(od.malware_count for od in otx_data_list)
	total_leaks = sum(ld.total_found for ld in leak_data_list)
	domains_monitored = len(otx_data_list)

	now = timezone.now()

	lang = report_settings.report_language if report_settings and report_settings.report_language else 'en'

	data = {
		'project': project,
		'lang': lang,
		'primary_color': primary_color,
		'secondary_color': secondary_color,
		'report_settings': report_settings,
		'classification_label': report_settings.classification_label if report_settings else 'CONFIDENTIAL - FOR INTERNAL USE ONLY',
		'document_number': report_settings.document_number if report_settings else '',
		'company_name': report_settings.company_name if report_settings else '',
		'company_address': report_settings.company_address if report_settings else '',
		'company_email': report_settings.company_email if report_settings else '',
		'company_website': report_settings.company_website if report_settings else '',
		'show_footer': report_settings.show_footer if report_settings else True,
		'footer_text': report_settings.footer_text if report_settings else 'CONFIDENTIAL',
		'report_date': now.strftime('%d %B %Y'),
		'report_time': now.strftime('%H:%M UTC'),
		'total_pulses': total_pulses,
		'total_malware': total_malware,
		'total_leaks': total_leaks,
		'domains_monitored': domains_monitored,
		'overall_risk': overall_risk,
		'banking_pulses': banking_pulses[:30],
		'banking_keywords': banking_keywords,
		'iocs': iocs,
		'cves': cves[:30],
		'severity_scores': severity_scores,
		'all_leaked_creds': all_leaked_creds[:200],
		'otx_data_list': otx_data_list,
		'leak_data_list': leak_data_list,
		'manual_indicators': manual_indicators,
	}

	if report_settings and report_settings.company_logo:
		data['company_logo_path'] = report_settings.company_logo.path

	template = get_template('threatIntel/report_banking.html')
	html = template.render(data)
	pdf = HTML(string=html).write_pdf()

	if 'download' in request.GET:
		response = HttpResponse(pdf, content_type='application/octet-stream')
		response['Content-Disposition'] = f'attachment; filename="threat_intel_report_{project.slug}_{now.strftime("%Y%m%d")}.pdf"'
	else:
		response = HttpResponse(pdf, content_type='application/pdf')

	return response


# ──────────────────────────────────────
# Report Settings
# ──────────────────────────────────────

def threat_report_settings(request, slug):
	"""Threat Intel report settings page."""
	settings_obj = ThreatIntelReportSetting.objects.first()

	if request.method == 'POST':
		if not settings_obj:
			settings_obj = ThreatIntelReportSetting()

		settings_obj.primary_color = request.POST.get('primary_color', '#1A237E')
		settings_obj.secondary_color = request.POST.get('secondary_color', '#0D1B2A')
		settings_obj.company_name = request.POST.get('company_name', '')
		settings_obj.company_address = request.POST.get('company_address', '')
		settings_obj.company_email = request.POST.get('company_email', '')
		settings_obj.company_website = request.POST.get('company_website', '')
		settings_obj.document_number = request.POST.get('document_number', '')
		settings_obj.show_footer = request.POST.get('show_footer') == 'on'
		settings_obj.footer_text = request.POST.get('footer_text', 'CONFIDENTIAL')
		settings_obj.report_language = request.POST.get('report_language', 'en')
		settings_obj.classification_label = request.POST.get('classification_label', 'CONFIDENTIAL - FOR INTERNAL USE ONLY')
		settings_obj.banking_keywords = request.POST.get('banking_keywords', '')

		if 'company_logo' in request.FILES:
			settings_obj.company_logo = request.FILES['company_logo']

		settings_obj.save()

		from django.contrib import messages
		messages.info(request, 'Threat Intel Report Settings updated.')
		from django.urls import reverse
		return http.HttpResponseRedirect(reverse('threat_report_settings', kwargs={'slug': slug}))

	context = {
		'settings_nav_active': 'active',
		'project': get_object_or_404(Project, slug=slug),
		'settings_obj': settings_obj,
		'primary_color': settings_obj.primary_color if settings_obj else '#1A237E',
		'secondary_color': settings_obj.secondary_color if settings_obj else '#0D1B2A',
	}
	return render(request, 'threatIntel/report_settings.html', context)
