TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.cpp \
    get_my_addr.cpp

HEADERS += \
    eth_arp.h \
    get_my_addr.h
