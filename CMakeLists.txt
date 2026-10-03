cmake_minimum_required(VERSION 2.8)
PROJECT(partoss CXX)
SET(p_sources archives.cpp attach.cpp buftomsg.cpp 
  buftopkt.cpp buftosqd.cpp chains.cpp control.cpp crc32.cpp environ.cpp
  errors.cpp handyman.cpp headers.cpp killold.cpp linkareb.cpp
  linkbase.cpp lowlevel.cpp morfiles.cpp msgtobuf.cpp
  packets.cpp parscomp.cpp parsmain.cpp parsrout.cpp partoss.cpp
  partpost.cpp partserv.cpp partset.cpp partsqd.cpp
  pkttobuf.cpp rebuild.cpp scanbase.cpp sqdtobuf.cpp version.cpp
  template.cpp times.cpp tossarcs.cpp _portlib.cpp mappath.cpp astring.cpp
  arealias.cpp locks.cpp netfwd.cpp
)
ADD_DEFINITIONS(-D_GNU_SOURCE -D_BSD_SOURCE)
ADD_EXECUTABLE(partoss ${p_sources})
