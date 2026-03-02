from django.db import models

from dashboard.models import Project
from targetApp.models import Domain


class OTXThreatData(models.Model):
	id = models.AutoField(primary_key=True)
	domain = models.ForeignKey(Domain, on_delete=models.CASCADE)
	project = models.ForeignKey(Project, on_delete=models.CASCADE)
	pulse_count = models.IntegerField(default=0)
	reputation = models.IntegerField(default=0)
	pulses = models.JSONField(default=list, blank=True)
	malware_samples = models.JSONField(default=list, blank=True)
	passive_dns = models.JSONField(default=list, blank=True)
	analyzed_urls = models.JSONField(default=list, blank=True)
	malware_count = models.IntegerField(default=0)
	passive_dns_count = models.IntegerField(default=0)
	url_count = models.IntegerField(default=0)
	whois_data = models.JSONField(default=dict, blank=True)
	fetched_at = models.DateTimeField(auto_now=True)
	fetch_error = models.TextField(null=True, blank=True)

	class Meta:
		unique_together = ('domain', 'project')

	def __str__(self):
		return f'OTX data for {self.domain.name}'


class LeakCheckData(models.Model):
	id = models.AutoField(primary_key=True)
	domain = models.ForeignKey(Domain, on_delete=models.CASCADE)
	project = models.ForeignKey(Project, on_delete=models.CASCADE)
	total_found = models.IntegerField(default=0)
	leaked_credentials = models.JSONField(default=list, blank=True)
	checked_credentials = models.JSONField(default=list, blank=True)
	fetched_at = models.DateTimeField(auto_now=True)
	fetch_error = models.TextField(null=True, blank=True)

	class Meta:
		unique_together = ('domain', 'project')

	def __str__(self):
		return f'LeakCheck data for {self.domain.name}'


class ThreatIntelScanStatus(models.Model):
	id = models.AutoField(primary_key=True)
	project = models.OneToOneField(Project, on_delete=models.CASCADE)
	is_scanning = models.BooleanField(default=False)
	last_scan_at = models.DateTimeField(null=True, blank=True)
	domains_scanned = models.IntegerField(default=0)
	domains_total = models.IntegerField(default=0)

	def __str__(self):
		return f'ThreatIntel scan status for {self.project.name}'


class ManualIndicator(models.Model):
	INDICATOR_TYPES = [
		('domain', 'Domain'),
		('subdomain', 'Subdomain'),
		('ip', 'IP Address'),
	]
	id = models.AutoField(primary_key=True)
	project = models.ForeignKey(Project, on_delete=models.CASCADE)
	indicator_type = models.CharField(max_length=20, choices=INDICATOR_TYPES)
	value = models.CharField(max_length=500)
	otx_data = models.JSONField(default=dict, blank=True)
	pulse_count = models.IntegerField(default=0)
	fetched_at = models.DateTimeField(null=True, blank=True)
	fetch_error = models.TextField(null=True, blank=True)
	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		unique_together = ('project', 'indicator_type', 'value')

	def __str__(self):
		return f'{self.indicator_type}: {self.value}'


class ThreatIntelReportSetting(models.Model):
	id = models.AutoField(primary_key=True)
	project = models.OneToOneField(Project, on_delete=models.CASCADE, null=True, blank=True)
	primary_color = models.CharField(max_length=10, null=True, blank=True, default='#1A237E')
	secondary_color = models.CharField(max_length=10, null=True, blank=True, default='#0D1B2A')
	company_name = models.CharField(max_length=100, null=True, blank=True)
	company_address = models.CharField(max_length=200, null=True, blank=True)
	company_email = models.CharField(max_length=100, null=True, blank=True)
	company_website = models.CharField(max_length=100, null=True, blank=True)
	company_logo = models.ImageField(upload_to='report_logos/', null=True, blank=True)
	document_number = models.CharField(max_length=100, null=True, blank=True)
	show_footer = models.BooleanField(default=True)
	footer_text = models.CharField(max_length=200, null=True, blank=True, default='CONFIDENTIAL')
	report_language = models.CharField(max_length=5, default='en', null=True, blank=True)
	classification_label = models.CharField(max_length=100, null=True, blank=True, default='CONFIDENTIAL - FOR INTERNAL USE ONLY')
	banking_keywords = models.TextField(
		null=True, blank=True,
		default='bank,banking,financial,swift,payment,atm,malware,trojan,phishing,credential,fraud',
	)

	def __str__(self):
		return f'TI Report Settings ({self.project.name})' if self.project else 'TI Report Settings (global)'
