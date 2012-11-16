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
				credenciais = UserCredentials(user=user)
				credenciais.save()
				login(request, user)
				return HttpResponseRedirect("dash")
			
		except:
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
	cred= UserCredentials.objects.get(user=request.user)
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
	return HttpResponse('')	


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
	print "teste"
	return HttpResponse("");