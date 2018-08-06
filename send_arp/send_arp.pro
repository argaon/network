TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += main.cpp \
    get_my_addr.cpp \
    arp_set.cpp \
    get_target_addr.cpp

HEADERS += \
    get_my_addr.h \
    arp_set.h \
    get_target_addr.h
