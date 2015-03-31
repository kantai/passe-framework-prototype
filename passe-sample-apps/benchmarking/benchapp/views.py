# Create your views here.

from django.http import HttpResponse
from benchmarking.benchapp.models import Foo


def i0(request):
    return HttpResponse("Hello, world. You're at the poll index %s." % 1)    
def i1(request):
    l = ""
    for i in range(0,1):
        l += str(len(Foo.objects.filter(databar="")))
    return HttpResponse("Hello, world. You're at the poll index %s." % l)    
def i2(request):
    l = ""
    for i in range(0,2):
        l += str(len(Foo.objects.filter(databar="")))
    return HttpResponse("Hello, world. You're at the poll index %s." % l)    
def i3(request):
    l = ""
    for i in range(0,3):
        l += str(len(Foo.objects.filter(databar="")))
    return HttpResponse("Hello, world. You're at the poll index %s." % l)    
def i4(request):
    l = ""
    for i in range(0,4):
        l += str(len(Foo.objects.filter(databar="")))
    return HttpResponse("Hello, world. You're at the poll index %s." % l)    
def i5(request):
    l = ""
    for i in range(0,5):
        l += str(len(Foo.objects.filter(databar="")))
    return HttpResponse("Hello, world. You're at the poll index %s." % l)    
def i6(request):
    l = ""
    for i in range(0,6):
        l += str(len(Foo.objects.filter(databar="")))
    return HttpResponse("Hello, world. You're at the poll index %s." % l)    
def i7(request):
    l = ""
    for i in range(0,7):
        l += str(len(Foo.objects.filter(databar="")))
    return HttpResponse("Hello, world. You're at the poll index %s." % l)    
def i8(request):
    l = ""
    for i in range(0,8):
        l += str(len(Foo.objects.filter(databar="")))
    return HttpResponse("Hello, world. You're at the poll index %s." % l)    
def i9(request):
    l = ""
    for i in range(0,9):
        l += str(len(Foo.objects.filter(databar="")))
    return HttpResponse("Hello, world. You're at the poll index %s." % l)    
def i10(request):
    l = ""
    for i in range(0,10):
        l += str(len(Foo.objects.filter(databar="")))
    return HttpResponse("Hello, world. You're at the poll index %s." % l)    
