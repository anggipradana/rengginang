import json
import logging

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.db.models import Count, Sum
from django.db.models.functions import TruncDay
from django.dispatch import receiver
from django.shortcuts import redirect, render, get_object_or_404
from django.utils import timezone
from django.http import HttpResponseRedirect, JsonResponse
from django.urls import reverse
from rolepermissions.roles import assign_role, clear_roles
from rolepermissions.decorators import has_permission_decorator
from django.template.defaultfilters import slugify


from startScan.models import *
from targetApp.models import Domain
from dashboard.models import *
from ReNgGinaNg.definitions import *
from threatIntel.models import OTXThreatData, LeakCheckData, ThreatIntelScanStatus, ManualIndicator
from threatIntel.views import _extract_iocs, _extract_cves, _fetch_otx_pulses, calculate_risk_score
from dashboard.models import OTXAlienVaultAPIKey


logger = logging.getLogger(__name__)

def index(request, slug):
    try:
        project = Project.objects.get(slug=slug)
    except Exception as e:
        # if project not found redirect to 404
        return HttpResponseRedirect(reverse('four_oh_four'))

    domains = Domain.objects.filter(project=project)
    subdomains = Subdomain.objects.filter(scan_history__domain__project__slug=project)
    endpoints = EndPoint.objects.filter(scan_history__domain__project__slug=project)
    scan_histories = ScanHistory.objects.filter(domain__project=project)
    vulnerabilities = Vulnerability.objects.filter(scan_history__domain__project__slug=project)
    scan_activities = ScanActivity.objects.filter(scan_of__in=scan_histories)

    domain_count = domains.count()
    endpoint_count = endpoints.count()
    scan_count = scan_histories.count()
    subdomain_count = subdomains.count()
    subdomain_with_ip_count = subdomains.filter(ip_addresses__isnull=False).count()
    alive_count = subdomains.exclude(http_status__exact=0).count()
    endpoint_alive_count = endpoints.filter(http_status__exact=200).count()

    info_count = vulnerabilities.filter(severity=0).count()
    low_count = vulnerabilities.filter(severity=1).count()
    medium_count = vulnerabilities.filter(severity=2).count()
    high_count = vulnerabilities.filter(severity=3).count()
    critical_count = vulnerabilities.filter(severity=4).count()
    unknown_count = vulnerabilities.filter(severity=-1).count()

    vulnerability_feed = vulnerabilities.order_by('-discovered_date')[:50]
    activity_feed = scan_activities.order_by('-time')[:50]
    total_vul_count = info_count + low_count + \
        medium_count + high_count + critical_count + unknown_count
    total_vul_ignore_info_count = low_count + \
        medium_count + high_count + critical_count
    last_week = timezone.now() - timedelta(days=7)

    count_targets_by_date = domains.filter(
        insert_date__gte=last_week).annotate(
        date=TruncDay('insert_date')).values("date").annotate(
            created_count=Count('id')).order_by("-date")
    count_subdomains_by_date = subdomains.filter(
        discovered_date__gte=last_week).annotate(
        date=TruncDay('discovered_date')).values("date").annotate(
            count=Count('id')).order_by("-date")
    count_vulns_by_date = vulnerabilities.filter(
        discovered_date__gte=last_week).annotate(
        date=TruncDay('discovered_date')).values("date").annotate(
            count=Count('id')).order_by("-date")
    count_scans_by_date = scan_histories.filter(
        start_scan_date__gte=last_week).annotate(
        date=TruncDay('start_scan_date')).values("date").annotate(
            count=Count('id')).order_by("-date")
    count_endpoints_by_date = endpoints.filter(
        discovered_date__gte=last_week).annotate(
        date=TruncDay('discovered_date')).values("date").annotate(
            count=Count('id')).order_by("-date")

    last_7_dates = [(timezone.now() - timedelta(days=i)).date()
                    for i in range(0, 7)]

    targets_in_last_week = []
    subdomains_in_last_week = []
    vulns_in_last_week = []
    scans_in_last_week = []
    endpoints_in_last_week = []

    for date in last_7_dates:
        _target = count_targets_by_date.filter(date=date)
        _subdomain = count_subdomains_by_date.filter(date=date)
        _vuln = count_vulns_by_date.filter(date=date)
        _scan = count_scans_by_date.filter(date=date)
        _endpoint = count_endpoints_by_date.filter(date=date)
        if _target:
            targets_in_last_week.append(_target[0]['created_count'])
        else:
            targets_in_last_week.append(0)
        if _subdomain:
            subdomains_in_last_week.append(_subdomain[0]['count'])
        else:
            subdomains_in_last_week.append(0)
        if _vuln:
            vulns_in_last_week.append(_vuln[0]['count'])
        else:
            vulns_in_last_week.append(0)
        if _scan:
            scans_in_last_week.append(_scan[0]['count'])
        else:
            scans_in_last_week.append(0)
        if _endpoint:
            endpoints_in_last_week.append(_endpoint[0]['count'])
        else:
            endpoints_in_last_week.append(0)

    targets_in_last_week.reverse()
    subdomains_in_last_week.reverse()
    vulns_in_last_week.reverse()
    scans_in_last_week.reverse()
    endpoints_in_last_week.reverse()

    context = {
        'dashboard_data_active': 'active',
        'domain_count': domain_count,
        'endpoint_count': endpoint_count,
        'scan_count': scan_count,
        'subdomain_count': subdomain_count,
        'subdomain_with_ip_count': subdomain_with_ip_count,
        'alive_count': alive_count,
        'endpoint_alive_count': endpoint_alive_count,
        'info_count': info_count,
        'low_count': low_count,
        'medium_count': medium_count,
        'high_count': high_count,
        'critical_count': critical_count,
        'unknown_count': unknown_count,
        'total_vul_count': total_vul_count,
        'total_vul_ignore_info_count': total_vul_ignore_info_count,
        'vulnerability_feed': vulnerability_feed,
        'activity_feed': activity_feed,
        'targets_in_last_week': targets_in_last_week,
        'subdomains_in_last_week': subdomains_in_last_week,
        'vulns_in_last_week': vulns_in_last_week,
        'scans_in_last_week': scans_in_last_week,
        'endpoints_in_last_week': endpoints_in_last_week,
        'last_7_dates': last_7_dates,
        'project': project
    }

    ip_addresses = IpAddress.objects.filter(ip_addresses__in=subdomains)

    context['total_ips'] = ip_addresses.count()
    context['most_used_port'] = Port.objects.filter(ports__in=ip_addresses).annotate(count=Count('ports')).order_by('-count')[:7]
    context['most_used_ip'] = ip_addresses.annotate(count=Count('ip_addresses')).order_by('-count').exclude(ip_addresses__isnull=True)[:7]
    context['most_used_tech'] = Technology.objects.filter(technologies__in=subdomains).annotate(count=Count('technologies')).order_by('-count')[:7]

    context['most_common_cve'] = CveId.objects.filter(cve_ids__in=vulnerabilities).annotate(nused=Count('cve_ids')).order_by('-nused').values('name', 'nused')[:7]
    context['most_common_cwe'] = CweId.objects.filter(cwe_ids__in=vulnerabilities).annotate(nused=Count('cwe_ids')).order_by('-nused').values('name', 'nused')[:7]
    context['most_common_tags'] = VulnerabilityTags.objects.filter(vuln_tags__in=vulnerabilities).annotate(nused=Count('vuln_tags')).order_by('-nused').values('name', 'nused')[:7]

    # Completed scans for VA report dropdown
    completed_scans = scan_histories.filter(scan_status=2).order_by('-start_scan_date')[:20]
    context['completed_scans'] = completed_scans

    # Threat Intel summary
    ti_otx = OTXThreatData.objects.filter(project=project)
    ti_leaks = LeakCheckData.objects.filter(project=project)
    ti_total_pulses = ti_otx.aggregate(total=Sum('pulse_count'))['total'] or 0
    ti_total_malware = ti_otx.aggregate(total=Sum('malware_count'))['total'] or 0
    ti_total_leaks = ti_leaks.aggregate(total=Sum('total_found'))['total'] or 0
    ti_domains_with_threats = ti_otx.filter(pulse_count__gt=0).count()
    ti_domains_with_leaks = ti_leaks.filter(total_found__gt=0).count()
    # Risk score — unified formula (TI + VA data)
    va_counts = {
        'critical': critical_count,
        'high': high_count,
        'medium': medium_count,
        'low': low_count,
    }
    ti_risk = calculate_risk_score(ti_otx, ti_leaks, va_counts=va_counts)
    ti_risk_score = ti_risk['total']
    ti_scan_status = ThreatIntelScanStatus.objects.filter(project=project).first()
    ti_has_data = ti_otx.exists() or ti_leaks.exists()

    context['ti_total_pulses'] = ti_total_pulses
    context['ti_total_malware'] = ti_total_malware
    context['ti_total_leaks'] = ti_total_leaks
    context['ti_domains_with_threats'] = ti_domains_with_threats
    context['ti_domains_with_leaks'] = ti_domains_with_leaks
    context['ti_risk_score'] = ti_risk_score
    context['ti_last_scan'] = ti_scan_status.last_scan_at if ti_scan_status else None
    context['ti_has_data'] = ti_has_data

    # Threat Intel IoC / CVE / Leak charts data
    if ti_has_data:
        all_pulses = []
        for od in ti_otx:
            for p in (od.pulses or []):
                all_pulses.append(p)
        manual_indicators = ManualIndicator.objects.filter(project=project)
        for mi in manual_indicators:
            for p in (mi.otx_data.get('pulses', []) if mi.otx_data else []):
                all_pulses.append(p)
        # Fetch subscribed pulses
        otx_key_obj = OTXAlienVaultAPIKey.objects.first()
        if otx_key_obj:
            all_pulses.extend(_fetch_otx_pulses(otx_key_obj.key, limit=20))

        iocs = _extract_iocs(all_pulses)
        cves = _extract_cves(all_pulses)

        context['ti_ioc_type_counts'] = {t: len(v) for t, v in iocs.items()}
        context['ti_total_iocs'] = sum(len(v) for v in iocs.values())
        context['ti_cves'] = cves[:20]

        # Leak per domain
        leak_per_domain = []
        for ld in ti_leaks:
            if ld.total_found > 0:
                leak_per_domain.append({'domain': ld.domain.name, 'count': ld.total_found})
        leak_per_domain.sort(key=lambda x: x['count'], reverse=True)
        context['ti_leak_per_domain'] = leak_per_domain[:10]

        # Threat per domain (pulse count)
        threat_per_domain = []
        for od in ti_otx:
            if od.pulse_count > 0:
                threat_per_domain.append({'domain': od.domain.name, 'count': od.pulse_count})
        threat_per_domain.sort(key=lambda x: x['count'], reverse=True)
        context['ti_threat_per_domain'] = threat_per_domain[:10]

    return render(request, 'dashboard/index.html', context)


def profile(request, slug):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(
                request,
                'Your password was successfully changed!')
            return redirect('profile')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'dashboard/profile.html', {
        'form': form
    })


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def admin_interface(request, slug):
    UserModel = get_user_model()
    users = UserModel.objects.all().order_by('date_joined')
    return render(
        request,
        'dashboard/admin.html',
        {
            'users': users
        }
    )

@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def admin_interface_update(request, slug):
    mode = request.GET.get('mode')
    user_id = request.GET.get('user')
    if user_id:
        UserModel = get_user_model()
        user = UserModel.objects.get(id=user_id)
    if request.method == 'GET':
        if mode == 'change_status':
            user.is_active = not user.is_active
            user.save()
    elif request.method == 'POST':
        if mode == 'delete':
            try:
                user.delete()
                messages.add_message(
                    request,
                    messages.INFO,
                    f'User {user.username} successfully deleted.'
                )
                messageData = {'status': True}
            except Exception as e:
                logger.error(e)
                messageData = {'status': False}
        elif mode == 'update':
            try:
                response = json.loads(request.body)
                role = response.get('role')
                change_password = response.get('change_password')
                clear_roles(user)
                assign_role(user, role)
                if change_password:
                    user.set_password(change_password)
                    user.save()
                messageData = {'status': True}
            except Exception as e:
                logger.error(e)
                messageData = {'status': False, 'error': str(e)}
        elif mode == 'create':
            try:
                response = json.loads(request.body)
                if not response.get('password'):
                    messageData = {'status': False, 'error': 'Empty passwords are not allowed'}
                    return JsonResponse(messageData)
                UserModel = get_user_model()
                user = UserModel.objects.create_user(
                    username=response.get('username'),
                    password=response.get('password')
                )
                assign_role(user, response.get('role'))
                messageData = {'status': True}
            except Exception as e:
                logger.error(e)
                messageData = {'status': False, 'error': str(e)}
        return JsonResponse(messageData)
    return HttpResponseRedirect(reverse('admin_interface', kwargs={'slug': slug}))


@receiver(user_logged_out)
def on_user_logged_out(sender, request, **kwargs):
    messages.add_message(
        request,
        messages.INFO,
        'You have been successfully logged out. Thank you ' +
        'for using ReNgGinaNg.')


@receiver(user_logged_in)
def on_user_logged_in(sender, request, **kwargs):
    messages.add_message(
        request,
        messages.INFO,
        'Hi @' +
        request.user.username +
        ' welcome back!')


def search(request, slug):
    return render(request, 'dashboard/search.html')


def four_oh_four(request):
    return render(request, '404.html')


def projects(request, slug):
    context = {}
    context['projects'] = Project.objects.all()
    return render(request, 'dashboard/projects.html', context)


@has_permission_decorator(PERM_MODIFY_TARGETS, redirect_url=FOUR_OH_FOUR_URL)
def delete_project(request, id):
    obj = get_object_or_404(Project, id=id)
    if request.method == "POST":
        obj.delete()
        responseData = {
            'status': 'true'
        }
        messages.add_message(
            request,
            messages.INFO,
            'Project successfully deleted!')
    else:
        responseData = {'status': 'false'}
        messages.add_message(
            request,
            messages.ERROR,
            'Oops! Project could not be deleted!')
    return JsonResponse(responseData)


def onboarding(request):
    context = {}
    error = ''

    # check is any projects exists, then redirect to project list else onboarding
    project = Project.objects.first()

    if project:
        slug = project.slug
        return HttpResponseRedirect(reverse('dashboardIndex', kwargs={'slug': slug}))

    if request.method == "POST":
        project_name = request.POST.get('project_name')
        slug = slugify(project_name)
        create_username = request.POST.get('create_username')
        create_password = request.POST.get('create_password')
        create_user_role = request.POST.get('create_user_role')
        key_openai = request.POST.get('key_openai')
        key_netlas = request.POST.get('key_netlas')
        key_chaos = request.POST.get('key_chaos')
        key_hackerone = request.POST.get('key_hackerone')
        username_hackerone = request.POST.get('username_hackerone')
        bug_bounty_mode = request.POST.get('bug_bounty_mode') == 'on'

        insert_date = timezone.now()

        try:
            Project.objects.create(
                name=project_name,
                slug=slug,
                insert_date=insert_date
            )
        except Exception as e:
            error = ' Could not create project, Error: ' + str(e)


        # update currently logged in user's preferences for bug bounty mode
        user_preferences, _ = UserPreferences.objects.get_or_create(user=request.user)
        user_preferences.bug_bounty_mode = bug_bounty_mode
        user_preferences.save()


        try:
            if create_username and create_password and create_user_role:
                UserModel = get_user_model()
                new_user = UserModel.objects.create_user(
                    username=create_username,
                    password=create_password
                )
                assign_role(new_user, create_user_role)


                # initially bug bounty mode is enabled for new user as selected for current user
                new_user_preferences, _ = UserPreferences.objects.get_or_create(user=new_user)
                new_user_preferences.bug_bounty_mode = bug_bounty_mode
                new_user_preferences.save()
                
        except Exception as e:
            error = ' Could not create User, Error: ' + str(e)

        if key_openai:
            openai_api_key = OpenAiAPIKey.objects.first()
            if openai_api_key:
                openai_api_key.key = key_openai
                openai_api_key.save()
            else:
                OpenAiAPIKey.objects.create(key=key_openai)

        if key_netlas:
            netlas_api_key = NetlasAPIKey.objects.first()
            if netlas_api_key:
                netlas_api_key.key = key_netlas
                netlas_api_key.save()
            else:
                NetlasAPIKey.objects.create(key=key_netlas)

        if key_chaos:
            chaos_api_key = ChaosAPIKey.objects.first()
            if chaos_api_key:
                chaos_api_key.key = key_chaos
                chaos_api_key.save()
            else:
                ChaosAPIKey.objects.create(key=key_chaos)

        if key_hackerone and username_hackerone:
            hackerone_api_key = HackerOneAPIKey.objects.first()
            if hackerone_api_key:
                hackerone_api_key.username = username_hackerone
                hackerone_api_key.key = key_hackerone
                hackerone_api_key.save()
            else:
                HackerOneAPIKey.objects.create(
                    username=username_hackerone, 
                    key=key_hackerone
                )

    context['error'] = error
    

    context['openai_key'] = OpenAiAPIKey.objects.first()
    context['netlas_key'] = NetlasAPIKey.objects.first()
    context['chaos_key'] = ChaosAPIKey.objects.first()
    context['hackerone_key'] = HackerOneAPIKey.objects.first().key if HackerOneAPIKey.objects.first() else ''
    context['hackerone_username'] = HackerOneAPIKey.objects.first().username if HackerOneAPIKey.objects.first() else ''

    context['user_preferences'], _ = UserPreferences.objects.get_or_create(
        user=request.user
    )

    return render(request, 'dashboard/onboarding.html', context)



def list_bountyhub_programs(request, slug):
    context = {}
    # get parameter to device which platform is being requested
    platform = request.GET.get('platform') or 'hackerone'
    context['platform'] = platform.capitalize()
    
    return render(request, 'dashboard/bountyhub_programs.html', context)