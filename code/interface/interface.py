#!/usr/bin/python

import pygame
import subprocess

display_width = 800
display_height = 600
 
black = (0,0,0)
white = (255,255,255)
gray = (125,125,125)
light_gray = (150,150,150)

webscan_directory = "/home/samuel/tfg/code/webscan.py"
#webscan_directory = "/home/pi/tfg/code/webscan.py"

def quit_program():
    pygame.display.quit()
    pygame.quit()
    quit()

def button(message,x,y,width,height,default_color,hover_color,action=None):
    mouse = pygame.mouse.get_pos()
    click = pygame.mouse.get_pressed()
    # If the mouse is hovering over the button:
    if x+width > mouse[0] > x and y+height > mouse[1] > y:
        pygame.draw.rect(programDisplay, hover_color,(x,y,width,height))
        if click[0] == 1 and action != None:
            action()         
    else:
        pygame.draw.rect(programDisplay, default_color,(x,y,width,height))

    smallText = pygame.font.SysFont("freesansbold.ttf",20)
    textSurf, textRect = text_objects(message, smallText)
    textRect.center = ( (x+(width/2)), (y+(height/2)) )
    programDisplay.blit(textSurf, textRect)

def text_objects(text, font):
    textSurface = font.render(text, True, black)
    return textSurface, textSurface.get_rect()

def program_start():
    while True:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                quit_program()              
        programDisplay.fill(white)
        largeText = pygame.font.Font("freesansbold.ttf",60)
        TextSurf, TextRect = text_objects("Web Application Scanner", largeText)
        TextRect.center = ((display_width/2),(display_height/3))
        programDisplay.blit(TextSurf, TextRect)
        button("Start scan",150,350,150,100,gray,light_gray,launch_scan)
        button("Quit",550,350,150,100,gray,light_gray,quit_program)
        pygame.display.update()
        clock.tick(15)
        
def launch_scan():
    subprocess.call(["gnome-terminal", "-x", webscan_directory])

pygame.init()
programDisplay = pygame.display.set_mode((display_width,display_height))
pygame.display.set_caption("Web Application Scanner")
clock = pygame.time.Clock()
program_start()
quit_program()
