cmake_minimum_required(VERSION 3.17)
project(keystroke_pam C)

set(CMAKE_C_STANDARD 99)

add_executable(keystroke_pam pam_keystroke.c keystroke_helper.c)