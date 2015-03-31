from django.conf.urls.defaults import patterns, include, url

# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
                           url(r'^1', 'benchmarking.benchapp.views.i1'),
                           url(r'^2', 'benchmarking.benchapp.views.i2'),
                           url(r'^3', 'benchmarking.benchapp.views.i3'),
                           url(r'^4', 'benchmarking.benchapp.views.i4'),
                           url(r'^5', 'benchmarking.benchapp.views.i5'),
                           url(r'^6', 'benchmarking.benchapp.views.i6'),
                           url(r'^7', 'benchmarking.benchapp.views.i7'),
                           url(r'^8', 'benchmarking.benchapp.views.i8'),
                           url(r'^9', 'benchmarking.benchapp.views.i9'),
                           url(r'^10', 'benchmarking.benchapp.views.i10'),
                           url(r'^0', 'benchmarking.benchapp.views.i0'),
    # url(r'^$', 'benchmarking.views.home', name='home'),
    # url(r'^benchmarking/', include('benchmarking.foo.urls')),

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # url(r'^admin/', include(admin.site.urls)),
)
