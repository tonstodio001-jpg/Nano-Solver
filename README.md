# Nano Solver v2  

"كنت ملان أسبوع… فرحت عملت القنبلة دي."  
— Rea · 16 سنة · معجب بـ Murder Drones & Undertale

- 54+ أمر في ملف واحد .py  
- 100% محلية · بدون API · بدون إنترنت في أغلب الأوامر  
- كل النتائج مفلترة تلقائياً من المحتوى الضار  
- آمنة على المستخدم والنظام · ethical by design  

## مميزات سريعة
- سكان مواقع ونظام كامل  
- تشغيل سيرفر HTTP بكلمة واحدة  
- تحليل ملفات + عرض صور وتشغيل أوديو  
- توليد باسووردات · هاشات · base64 · بحث GitHub مفلتر  
- مراقبة سلوك النظام · وأكثر من 50 أمر…

# README

## تثبيت المتطلبات

### Windows
pip install kivy[base] requests psutil reportlab dnspython python-whois yara-python pygame

### Linux/Ubuntu
sudo apt update
sudo apt install python3-pip python3-dev python3-venv
pip install kivy[base] requests psutil reportlab dnspython python-whois yara-python pygame

### macOS
brew install pkg-config sdl2 sdl2_image sdl2_ttf sdl2_mixer
pip install kivy[base] requests psutil reportlab dnspython python-whois yara-python pygame

### إذا فشل تثبيت yara-python
pip install kivy[base] requests psutil reportlab dnspython python-whois pygame

### تثبيت من requirements.txt
pip install -r requirements.txt

### اختبار كل شيء
python3 - <<EOF
import kivy
import requests
import psutil
import reportlab
import dns
import whois
import yara
import pygame

print("everything working!")
EOF
