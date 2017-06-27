#!/usr/bin/python

import pygame
import subprocess

pygame.init()

# Width and height are set to the screen resolution
w = pygame.display.Info().current_w
h = pygame.display.Info().current_h

black = (0,0,0)
white = (255,255,255)
green = (0, 200, 0)
light_green = (25, 255, 25)
red = (200, 0, 0)
light_red = (255, 25, 25)

menu_font = "freesans"
code_font = "couriernew"

# Font sizes are relative to screen width
small_text = int(w/40)
medium_text = int(w/30)
big_text = int(w/15)

webscan_directory = "/home/samuel/tfg/code/webscan.py"
#webscan_directory = "/home/pi/tfg/code/webscan.py"

def quit_program():
    pygame.display.quit()
    pygame.quit()
    quit()

def print_text(message, font, font_size, bold, center_x, center_y):
    while True:
        text_format = pygame.font.SysFont(font, font_size, bold)
        text_surf = text_format.render(message, True, black)
        text_rect = text_surf.get_rect()
        # If the message is too wide to properly fit the screen, shrink it and try again
        if text_rect[2] >= w*0.9: 
            font_size -= 1
        else: # If the font has a reasonable size, write it to the screen
            break
    text_rect.center = (center_x, center_y)
    programDisplay.blit(text_surf, text_rect)

def button(message,x,y,width,height,default_color,hover_color,action=None):
    mouse = pygame.mouse.get_pos()
    click = pygame.mouse.get_pressed()
    # If the mouse is hovering over the button:
    if x+width > mouse[0] > x and y+height > mouse[1] > y:
        pygame.draw.rect(programDisplay, hover_color, (x,y,width,height))
        if click[0] == 1 and action != None: # If clicking
            action()         
    else:
        pygame.draw.rect(programDisplay, default_color, (x,y,width,height)) 
    print_text(message, menu_font, medium_text, False, x+(width/2), y+(height/2))

def main_menu():
    while True:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                quit_program()              
        programDisplay.fill(white)
        print_text("Web Application Scanner", menu_font, big_text, True, w/2, h/5)
        button("Start scan", w*2/5, h/2.5, w/5, h/5, green, light_green, launch_scan)
        button("Quit", w*2/5, h/1.5, w/5, h/5, red, light_red, quit_program)
        pygame.display.update()        
        clock.tick(15)

def remove_trailing_newline(message):
    if message.endswith("\n"):
        return message[:-1]
    return message

def fetch_output(pid, message_list):
    message = pid.stdout.readline().decode("utf-8")
    message = remove_trailing_newline(message)
    if message != '':
        message_list.append(message)
    return message, message_list

def display_messages(message_list):
    programDisplay.fill(white)
    message_list = list(reversed(message_list))
    for i in range(len(message_list)):
        if i == 0: # Bold text for the current (newest) message
            print_text("> " + message_list[i] + " <", code_font, medium_text, True, w/2, h/1.2)
        else: # Non-bold text for old messages
            print_text(message_list[i], code_font, small_text, False, w/2, h/1.2 - (i*h/10))
    pygame.display.update()        
    clock.tick(15)

def launch_scan():
    pid = subprocess.Popen(webscan_directory, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    message_list=[]
    while True:
        message, message_list = fetch_output(pid, message_list)
        display_messages(message_list)
        if message == '' and pid.poll() != None: # Once the scan is done, return to main menu
            break
    main_menu()

programDisplay = pygame.display.set_mode((w,h))
pygame.display.set_caption("Web Application Scanner")
clock = pygame.time.Clock()
main_menu()
quit_program()
