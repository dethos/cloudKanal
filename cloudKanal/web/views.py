# -*- coding: utf-8 -*-
# Create your views here.
from models import UserCredentials, Channel, Item
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout

from django.shortcuts import render_to_response
from django.http import HttpResponse, HttpResponseRedirect
from django.template import RequestContext
from django.contrib.auth.decorators import login_required

from rauth.service import OAuth2Service
import requests
import simplejson as json

def home(request):
    if request.user.is_authenticated():
        return HttpResponseRedirect("dash")
    else:
        return render_to_response("home.html", {}, context_instance=RequestContext(request))

def ulogin(request):
    message = "Use o formulário para efectuar login"
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        try:
            reg = request.POST['registo']
            try:
                user = User.objects.get(username=username)
                message = "Utilizador já em uso"
                return render_to_response("home.html", {'message':message}, context_instance=RequestContext(request))
            except:
                user = User(username=username)
                user.set_password(password)
                user.save()
                credenciais = UserCredentials()
                credenciais.user = user
                credenciais.token_cloud = ""
                credenciais.token_kanal = ""
                credenciais.secret_cloud = ""
                credenciais.last = ""
                credenciais.save()
                user = authenticate(username=username, password=password)
                login(request, user)
                return HttpResponseRedirect("dash")
            
        except:
            return render_to_response("home.html", {'message':"erro"}, context_instance=RequestContext(request))
            user = authenticate(username=username, password=password)
            if user is not None:
                if user.is_active:
                    login(request, user)
                    return HttpResponseRedirect("dash")
                else:
                    message = " A tua conte foi desactivada"
            else:
                message = "User ou password inválidos"

    return render_to_response("home.html", {'message':message}, context_instance=RequestContext(request))

@login_required
def quit(request):
    logout(request)
    return HttpResponseRedirect('/')

@login_required
def dashboard(request):
    cred = UserCredentials.objects.get(user=request.user)
    if (cred.token_cloud):
        ativo_cloud = False
        estado_cloud = "Os dados do serviço cloudpt já se encontram introduzidos."
    else:
        ativo_cloud = True
        estado_cloud = "Siga o link seguinte para autorizar o acesso à sua conta cloudpt"

    if (cred.token_kanal):
        ativo_kanal = False
        estado_kanal = "Os dados do serviço MEO Kanal já se encontram introduzidos."
    else:
        ativo_kanal = True
        estado_kanal = "Siga o link seguinte para autorizar o acesso à sua conta MEO Kanal"
    return render_to_response("dash.html", {"ativo_kanal":ativo_kanal, "ativo_cloud":ativo_cloud, "estado_kanal":estado_kanal, "estado_cloud":estado_cloud}, context_instance=RequestContext(request))


@login_required
def getCloudToken(request):
    cloud = OAuth1Service (
        name='CodebitsAPP',
        consumer_key='b36e70f8-d8c1-4805-8402-bd06cdc432dc',
        consumer_secret='53769013013732849764145905535233908903',
        access_token_url='https://cloudpt.pt/oauth/access_token',
        authorize_url='https://cloudpt.pt/oauth/authorize',
        request_token_url='https://cloudpt.pt/oauth/request_token',
        header_auth=True)

    request_token, request_token_secret = \
    cloud.get_request_token(method='GET')

    authorize_url = cloud.get_authorize_url(request_token)

    try:
        pin = request.GET['pin']
        response = cloud.get_access_token('GET',
                                         request_token=request_token,
                                         request_token_secret=request_token_secret,
                                         params={'oauth_verifier': pin})
        data = response.content

        access_token = data['oauth_token']
        access_token_secret = data['oauth_token_secret']

        credenciais = UserCredentials.objects.get(user=request.user)
        credenciais.token_cloud = access_token
        credenciais.secret_cloud = access_token_secret
        credenciais.save()

    except:
        return HttpResponseRedirect(authorize_url)


@login_required
def getKanalToken(request):
    redirect_uri = "http://www.google.pt"

    MEOKanal = OAuth2Service (
        name='Codebits2012',
        consumer_key='6f02819ed48f061655965f63cc324592d464115ba524f78bed7e9c98b6139a6b',
        consumer_secret='56e58fc9e6602ac1ba319fba34fb14ab91f03743edfc629781fe752372d70aa5',
        access_token_url='https://kanal.pt/api/oauth/access_token',
        authorize_url='https://kanal.pt/api/oauth'
    )

    try:
        code = request.GET['code']
        
        data = dict(code=code,
        grant_type='authorization_code',
        redirect_uri=redirect_uri)

        access_token = \
            MEOKanal.get_access_token('POST', data=data).content['access_token']

        credenciais = UserCredentials.objects.get(user=request.user)
        credenciais.token_kanal = access_token
        credenciais.save()
        return HttpResponseRedirect("dash")

    except:

        authorize_url = MEOKanal.get_authorize_url(redirect_uri=redirect_uri,
            scope='channel.list')

        return HttpResponseRedirect(authorize_url)



def sync_services(request):
    users = User.objects.all()
    for user in users:
        credencial = UserCredentials.objects.get(user=user)
        changes(credencial, "/")
    return HttpResponse("");


##Auxiliares
def changes(credencial, path):
    content = getCloudContent(path)
    last = json.loads(credential.last)
    if content['hash'] != last['hash']:
        for item in content['contents']:
            if item['is_dir'] is False:
                verifyChanges(item, last)
        updateRemoved(content, last)
        return


def verifyChanges(item, last):
    for old in last['contents']:
        if old['path'] == item['path'] and old['modified'] != item['modified']:
            removeKanalItem(item['path'])
            uploadItem(item['path'])
            return
    uploadItem(item['path'])
    return

def removeKanalItem(path):
    pass

def uploadItem(path):
    pass

def UpdateRemovedItem(path):
    pass     

def getCloudContent(path):
    pass
