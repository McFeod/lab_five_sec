import os

from des import cbc
from constants import order
from report.jinja_settings import render_template


OUT_DIR = 'out'
TEMP_FILE = 'report.tex'
OUT_FILE = 'report.pdf'


def show_report(template, context, out_dir=OUT_DIR, tex_file=TEMP_FILE, pdf_file=OUT_FILE):
    tex = render_template(template, context)
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
    os.chdir(out_dir)
    with open(tex_file, 'w+') as f:
        f.write(tex)
    os.system('pdflatex {}'.format(tex_file))
    # os.system('pdflatex {} > /dev/null'.format(tex_file))
    os.system('evince {} > /dev/null'.format(pdf_file))


if __name__ == '__main__':

    message = 'Федосеев'
    context = {
        'func': {
            'str': str
        },
        'des': cbc('Федосеев', 'Георгий'),
        'const': order
    }
    show_report('templates/main.tex', context)
