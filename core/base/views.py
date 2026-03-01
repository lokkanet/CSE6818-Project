from django.shortcuts import render
from django.contrib import admin
from django.views.generic import View
from .models import NetworkPacket, BitTorrentPacket

from django.http import JsonResponse
from django.views import View
from django.contrib.admin.views.decorators import staff_member_required
from django.utils.decorators import method_decorator

# flag to check the process
running = False


class TraceNetworkView(View):
    def get(self, request):
        ctx = admin.site.each_context(request)
        ctx['counts'] = {
            'Network': 10,
            'BitTorrent': 10,
        }
        return render(request, 'base/admin_home.html', ctx)


@method_decorator(staff_member_required, name='dispatch')
class RunProcessView(View):
    def post(self, request):
        global running
        running = True
        if running:
            print("running running")
        # your python code here
        return JsonResponse({'status': 'started'})


@method_decorator(staff_member_required, name='dispatch')
class StopProcessView(View):
    def post(self, request):
        global running
        running = False
        return JsonResponse({'status': 'stopped'})


import subprocess
import os
import signal
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

# Store process globally (use a DB or cache for multi-worker setups)
running_process = None




@csrf_exempt
def start_program(request):
    global running_process

    if running_process and running_process.poll() is None:
        return JsonResponse({"status": "already_running"})

    # Replace with your actual script path
    running_process = subprocess.Popen(
        # ["python", "utils/model_helpers/catch_packets.py"],
        ["python", "manage.py", "catch_packets"],

        # stdout=subprocess.PIPE,
        #     stderr=subprocess.PIPE,
    )
    return JsonResponse({"status": "started", "pid": running_process.pid})




@csrf_exempt
def stop_program(request):
    global running_process

    if running_process and running_process.poll() is None:
        os.kill(running_process.pid, signal.SIGTERM)
        running_process = None
        return JsonResponse({"status": "stopped"})

    return JsonResponse({"status": "not_running"})


def index(request):
    return render(request, "index.html")
