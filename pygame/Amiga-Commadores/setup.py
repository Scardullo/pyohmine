import cx_Freeze, glob, os

os.environ['TCL_LIBRARY'] = r'C:\Users\Jagraj\AppData\Local\Programs\Python\Python35-32\tcl\tcl8.6'
os.environ['TK_LIBRARY'] = r'C:\Users\Jagraj\AppData\Local\Programs\Python\Python35-32\tcl\tk8.6'

files = glob.glob('images/*.png') + glob.glob('images/*.txt') + glob.glob('levels/*.png') + glob.glob('sound/*.ogg') + glob.glob('fonts/*.ttf')
files.append('data.txt')
files.append('level_colors.py')
exes = [cx_Freeze.Executable('main.py')]

cx_Freeze.setup(
	name = 'Alien Adventures',
	options = {'build_exe': {	"packages":['pygame', 'threading', 'itertools', 'random', 'os', 'glob'], 
								"include_files":files}},
	executables = exes
	)