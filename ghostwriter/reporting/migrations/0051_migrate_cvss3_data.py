from django.db import migrations

def migrate_cvss3_data(apps, schema_editor):
    Finding = apps.get_model('reporting', 'Finding')
    ReportFindingLink = apps.get_model('reporting', 'ReportFindingLink')
    CVSSRating = apps.get_model('reporting', 'CVSSRating')

    for finding in Finding.objects.all():
        if finding.cvss_score is not None and finding.cvss_vector:
            cvss_rating, created = CVSSRating.objects.get_or_create(
                version='3.0',
                score=finding.cvss_score,
                vector=finding.cvss_vector
            )
            finding.cvss_ratings.add(cvss_rating)

    for report_finding in ReportFindingLink.objects.all():
        if report_finding.cvss_score is not None and report_finding.cvss_vector:
            cvss_rating, created = CVSSRating.objects.get_or_create(
                version='3.0',
                score=report_finding.cvss_score,
                vector=report_finding.cvss_vector
            )
            report_finding.cvss_ratings.add(cvss_rating)

def remove_cvss3_data(apps, schema_editor):
    CVSSRating = apps.get_model('reporting', 'CVSSRating')
    CVSSRating.objects.filter(version='3.0').delete()

class Migration(migrations.Migration):

    dependencies = [
        ('reporting', '0050_auto_20240526_1532'),
    ]

    operations = [
        migrations.RunPython(migrate_cvss3_data, remove_cvss3_data),
        migrations.RemoveField(
            model_name='finding',
            name='cvss_score',
        ),
        migrations.RemoveField(
            model_name='finding',
            name='cvss_vector',
        ),
        migrations.RemoveField(
            model_name='reportfindinglink',
            name='cvss_score',
        ),
        migrations.RemoveField(
            model_name='reportfindinglink',
            name='cvss_vector',
        ),
    ]
