from distutils.core import setup
from distutils.extension import Extension
from Cython.Build import cythonize

extensions = [
	Extension("spsecure",["SPSecureAPI.pyx"],
			include_dirs = [r"C:\Users\Beeven\Desktop\Crypto\AppData"],
			library_dirs = [r"C:\Users\Beeven\Desktop\Crypto\AppData"]
		)
]

setup(
	name = "SPSecureAPI ext",
	ext_modules = cythonize(extensions),
)