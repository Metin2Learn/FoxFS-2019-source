import glob
import os

os.system( "PropertyGen.exe ../Client/property" )
os.system( "move property.xml ../Client/root/property.xml" )