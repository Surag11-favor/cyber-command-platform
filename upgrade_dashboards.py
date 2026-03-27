import glob
import re

files = glob.glob('src/main/resources/templates/*.html')
for f in files:
    if 'index.html' in f or 'login.html' in f or 'register.html' in f:
        continue
    with open(f, 'r', encoding='utf-8') as file:
        content = file.read()
    content = content.replace('<div class="hud-background"></div>', '<div class="orbital-glow"></div>')
    content = content.replace('<div class="data-stream"></div>', '<div class="orbital-glow-2"></div>')
    content = content.replace('--cyber-cyan', '--neon-cyan')
    content = content.replace('--cyber-purple', '--neon-purple')
    content = content.replace('btn-elite', 'btn-ultramodern px-4 text-center d-block text-decoration-none')
    content = content.replace('tactical-glow', '')
    content = content.replace('family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;700', 'family=Outfit:wght@300;400;600;800;900')
    
    with open(f, 'w', encoding='utf-8') as file:
        file.write(content)
