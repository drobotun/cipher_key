TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.c \
    cipher_key.c \
    gost_3411_2012_calc.c

HEADERS += \
    cipher_key.h \
    gost_3411_2012_calc.h \
    gost_3411_2012_const.h \
    cipher_key_test.h
