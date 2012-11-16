from django.conf.urls import patterns, include, url
from web.views import home, dashboard, getCloudToken, getKanalToken, ulogin, quit
# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    url(r'^$', home),
    url(r'^dash$', dashboard),
    url(r'^login$', ulogin),
    url(r'^logout$', quit),
    url(r'^cloudtoken$', getCloudToken),
    url(r'^kanaltoken$', getKanalToken),
    # url(r'^cloudKanal/', include('cloudKanal.foo.urls')),

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    url(r'^admin/', include(admin.site.urls)),
)
