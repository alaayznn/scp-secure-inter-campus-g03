"""Render retained M1 Markdown sources to PDFs. No installation, network or lab calls."""
import html
import argparse
import json
import os
import re
import struct
import unicodedata
from datetime import datetime, timezone, timedelta
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                                 Flowable, KeepTogether, CondPageBreak)

ROOT = Path(__file__).resolve().parents[1]
CFG = json.loads((ROOT / 'project.json').read_text(encoding='utf-8'))
GID = CFG['group_id']
if GID is None:
    raise SystemExit('Confirm group_id before final rendering')
G = str(int(GID))
PAGE_W, PAGE_H = A4
WIDTH = PAGE_W - 96
FONT_DIR = Path(os.environ.get('WINDIR', 'C:/Windows')) / 'Fonts'
font = Path(os.environ.get('SCP_FONT', str(FONT_DIR / 'arial.ttf')))
bold = Path(os.environ.get('SCP_FONT_BOLD', str(FONT_DIR / 'arialbd.ttf')))
pdfmetrics.registerFont(TTFont('SCP', str(font)))
pdfmetrics.registerFont(TTFont('SCP-Bold', str(bold)))
pdfmetrics.registerFontFamily('SCP', normal='SCP', bold='SCP-Bold', italic='SCP', boldItalic='SCP-Bold')
NAVY = colors.HexColor('#12304a')
BLUE = colors.HexColor('#1f789c')
PALE = colors.HexColor('#edf4f8')
GRAY = colors.HexColor('#526473')
STYLES = {
    'title': ParagraphStyle('Title', fontName='SCP-Bold', fontSize=25, leading=29, textColor=NAVY, spaceAfter=13),
    'h2': ParagraphStyle('Heading2', fontName='SCP-Bold', fontSize=13, leading=17, textColor=BLUE, spaceBefore=12, spaceAfter=7, keepWithNext=True),
    'body': ParagraphStyle('Body', fontName='SCP', fontSize=10, leading=14, textColor=NAVY, spaceAfter=8, splitLongWords=True, allowWidows=0, allowOrphans=0),
    'cell': ParagraphStyle('Cell', fontName='SCP', fontSize=8.8, leading=12.2, textColor=NAVY),
    'th': ParagraphStyle('TH', fontName='SCP-Bold', fontSize=9, leading=12, textColor=colors.white),
    'name': ParagraphStyle('Name', fontName='SCP', fontSize=12, leading=18, textColor=NAVY, alignment=TA_RIGHT),
}

def subst(text):
    for k, v in {'{{GG}}': GID, '{{G}}': G, '{{DATE}}': CFG['prepared_on']}.items():
        text = text.replace(k, v)
    return text

def para(text, style='body'):
    return Paragraph(html.escape(subst(text)), STYLES[style])

def table(rows, widths=None):
    count = len(rows[0])
    if widths is None:
        proportions = {2: [0.28, 0.72], 3: [0.29, 0.35, 0.36]}.get(count, [1/count]*count)
        widths = [WIDTH*x for x in proportions]
    cells = [[para(c, 'th' if i == 0 else 'cell') if isinstance(c, str) else c for c in row] for i, row in enumerate(rows)]
    obj = Table(cells, colWidths=widths, repeatRows=1, hAlign='LEFT')
    obj.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), NAVY), ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, PALE]),
        ('LINEBELOW', (0,0), (-1,0), 0.5, NAVY),
        ('LINEBELOW', (0,1), (-1,-1), 0.35, colors.HexColor('#cbd9e2')),
        ('LEFTPADDING', (0,0), (-1,-1), 8), ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 6), ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    return obj

def arabic_visual(name):
    # Contextual Unicode presentation forms for Arabic-only names. Original Unicode
    # names remain unchanged in project.json. No mixed-direction text is processed.
    forms = {}
    for cp in range(0xFE70, 0xFEFF + 1):
        decomp = unicodedata.decomposition(chr(cp)).split()
        if len(decomp) == 2 and decomp[0] in ('<isolated>', '<final>', '<initial>', '<medial>'):
            forms.setdefault(chr(int(decomp[1], 16)), {})[decomp[0][1:-1]] = chr(cp)
    shaped = []
    for i, ch in enumerate(name):
        f = forms.get(ch, {})
        prev = forms.get(name[i-1], {}) if i else {}
        nxt = forms.get(name[i+1], {}) if i+1 < len(name) else {}
        left = 'initial' in prev and 'final' in f
        right = 'initial' in f and 'final' in nxt
        kind = 'medial' if left and right else 'final' if left else 'initial' if right else 'isolated'
        shaped.append(f.get(kind, ch))
    return ''.join(reversed(shaped))

def baseline_table():
    log=ROOT/'evidence/sanitized_logs/M1_runtime_checks.json'
    data=json.loads(log.read_text(encoding='utf-8'))
    if data.get('result')!='PASS': raise ValueError('A successful real runtime report is required')
    pcap=data['pcap']; raw=(ROOT/pcap['path']).read_bytes()
    endian={b'\xd4\xc3\xb2\xa1':'<',b'\xa1\xb2\xc3\xd4':'>'}.get(raw[:4])
    if not endian: raise ValueError('Expected classic tcpdump PCAP')
    offset=24; packets=0
    while offset<len(raw):
        _,_,length,_=struct.unpack(endian+'IIII',raw[offset:offset+16])
        offset+=16+length; packets+=1
    if offset!=len(raw): raise ValueError('Truncated PCAP')
    stamp=float(data['http_packets'][0][1])
    utc=datetime.fromtimestamp(stamp,timezone.utc)
    local=utc.astimezone(timezone(timedelta(hours=3)))
    rows=[['Observed item','Verified result'],
          ['WAN capture',f'gw-hq {data["wan_interface"]}, 172.16.{G}.10/24; {packets} packets, {len(raw)} bytes.'],
          ['HTTP time',utc.strftime('%d/%m/%Y %H:%M:%S UTC')+' / '+local.strftime('%H:%M:%S Asia/Amman')],
          ['Request / response','Frame 4: GET /baseline.txt. Frame 6: HTTP 200 and '+pcap['known_marker']+' in readable payload.'],
          ['Validation',f'{len(data["checks"])} runtime checks PASS; six healthy nodes, isolated networks and no VPN.'],
          ['SHA-256',pcap['sha256']]]
    return table(rows)

def submission_links():
    url=CFG['repository']['url']
    entries=[('GitHub repository',url,url),
             ('Real WAN capture',url+'/blob/main/evidence/pcaps/M1_baseline_wan.pcap','evidence/pcaps/M1_baseline_wan.pcap'),
             ('Reproducible results',url+'/blob/main/evidence/sanitized_logs/M1_runtime_checks.json','evidence/sanitized_logs/M1_runtime_checks.json')]
    rows=[['Resource','Clickable link']]
    for label,target,display in entries:
        link=Paragraph('<link href="'+html.escape(target,quote=True)+'" color="#176b91">'+html.escape(display)+'</link>',STYLES['cell'])
        rows.append([label,link])
    return table(rows)

class Diagram(Flowable):
    def __init__(self, kind):
        Flowable.__init__(self)
        self.kind = kind
        self.width = WIDTH
        self.height = {'TOPOLOGY': 298, 'PKI': 174, 'TLS': 280, 'IKE': 238, 'KERBEROS': 343}[kind]

    def label(self, text, x, y, width, size=9, align='center', color=NAVY):
        p = Paragraph(html.escape(subst(text)), ParagraphStyle('D', fontName='SCP', fontSize=size, leading=size+3, textColor=color, alignment=1 if align=='center' else 0))
        _, h = p.wrap(width, 100)
        p.drawOn(self.canv, x, y-h)
        return h

    def arrow(self, x1, y1, x2, y2, color=BLUE, dashed=False):
        c = self.canv
        c.setStrokeColor(color); c.setFillColor(color); c.setLineWidth(1)
        c.setDash(3,3) if dashed else c.setDash()
        c.line(x1,y1,x2,y2); c.setDash()
        import math
        ang = math.atan2(y2-y1, x2-x1)
        p=c.beginPath(); p.moveTo(x2,y2)
        p.lineTo(x2-6*math.cos(ang-.4), y2-6*math.sin(ang-.4))
        p.lineTo(x2-6*math.cos(ang+.4), y2-6*math.sin(ang+.4)); p.close()
        c.drawPath(p,fill=1,stroke=0)

    def box(self, x,y,w,h,title,body,fill=PALE,dashed=False):
        c=self.canv; c.setStrokeColor(BLUE); c.setFillColor(fill)
        c.setDash(4,3) if dashed else c.setDash()
        c.roundRect(x,y,w,h,7,fill=1,stroke=1); c.setDash()
        self.label(title,x+6,y+h-8,w-12,10)
        self.label(body,x+8,y+h-30,w-16,8.8)

    def draw(self):
        c=self.canv
        if self.kind == 'TOPOLOGY':
            self.box(0,139,151,142,'Branch LAN','10.{{G}}.2.0/24',dashed=True)
            self.box(170,139,151,142,'Untrusted WAN','172.16.{{G}}.0/24',fill=colors.HexColor('#fff3e5'),dashed=True)
            self.box(340,139,159,142,'HQ LAN','10.{{G}}.1.0/24',dashed=True)
            self.label('client-br .2.10',8,217,135)
            self.label('gw-branch .2.1 / WAN .20',8,182,135,8.6)
            self.label('attacker .66',180,211,131)
            self.label('gw-branch .20 -> gw-hq .10',180,174,131,8.3)
            self.label('web-hq .1.10 | kdc .1.20',349,217,140,8.4)
            self.label('gw-hq .1.1 / WAN .10',349,182,140,8.6)
            self.arrow(120,193,377,193)
            self.label('Baseline: HTTP clear | Target: ESP across WAN',65,131,370,9)
            self.box(0,16,216,82,'Offline Root CA','Outside Docker and repository; no network interface',fill=colors.HexColor('#e9f5ed'),dashed=True)
            self.box(280,16,219,82,'Controlled Issuing CA activity','Public certificates / CRLs delivered to roles; signing key not in service mounts')
            self.arrow(216,56,280,56,dashed=True)
            self.arrow(390,98,419,139,dashed=True)
        elif self.kind == 'PKI':
            self.box(10,94,186,69,'Offline Root CA','P-384 | CA:TRUE | pathlen 1',fill=colors.HexColor('#e9f5ed'))
            self.box(280,94,207,69,'Issuing CA','P-384 | CA:TRUE | pathlen 0')
            self.arrow(196,127,280,127)
            self.label('signs',202,149,72,8)
            self.box(85,2,400,59,'End-entity profiles','Portal + 2 gateways + >=3 staff (staff03 revoked later)')
            self.arrow(383,94,383,61)
        else:
            if self.kind == 'TLS':
                parties=['Client C', 'Portal S']
                msgs=[(0,1,'ClientHello: random, SNI, TLS1.3, key_share'),
                      (1,0,'ServerHello: suite, fresh key_share'),
                      (1,0,'{EncryptedExtensions, [CertificateRequest]}'),
                      (1,0,'{Certificate, CertificateVerify, Finished}'),
                      (0,1,'{[Certificate, CertificateVerify], Finished}'),
                      (0,1,'Application traffic: HTTP / or /staff/ over TLS')]
            elif self.kind == 'IKE':
                parties=['gw-branch (I)', 'gw-hq (R)']
                msgs=[(0,1,'IKE_SA_INIT: HDR, SAi1, KEi, Ni'),
                      (1,0,'IKE_SA_INIT: HDR, SAr1, KEr, Nr, [CERTREQ]'),
                      (0,1,'IKE_AUTH: SK{IDi, CERT, AUTH, SAi2, TSi, TSr}'),
                      (1,0,'IKE_AUTH: SK{IDr, CERT, AUTH, SAr2, TSi, TSr}')]
            else:
                parties=['Client C','KDC AS/TGS','Service S']
                msgs=[(0,1,'1 AS_REQ: identity, n1, AEAD preauth'),
                      (1,0,'2 AS_REP: TGT + protected R_CT,n1,expiry'),
                      (0,1,'3 TGS_REQ: TGT + protected S,n2,time'),
                      (1,0,'4 TGS_REP: ST + protected R_CS,n2,expiry'),
                      (0,2,'5 AP_REQ: ST + protected n3,time,context'),
                      (2,0,'6 AP_REP: protected echo n3,new nS,context'),
                      (0,2,'7 AP_FINISH: protected echo nS,context')]
            xs=[35,WIDTH-35] if len(parties)==2 else [30,WIDTH/2,WIDTH-30]
            top=self.height-5
            for x,title in zip(xs,parties):
                self.label(title,x-75,top,150,10)
                c.setStrokeColor(colors.HexColor('#b5c9d5')); c.setDash(3,3)
                c.line(x,top-27,x,10); c.setDash()
            step=(self.height-55)/len(msgs)
            for i,(a,b,msg) in enumerate(msgs):
                y=top-49-i*step
                self.arrow(xs[a],y,xs[b],y)
                start=min(xs[a],xs[b]); span=abs(xs[a]-xs[b])
                # Label above each arrow, wrapped within its lane span.
                self.label(msg,start+6,y+30,span-12,8.3)

def footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor('#c6d7e1')); canvas.line(48,39,PAGE_W-48,39)
    canvas.setFont('SCP',8); canvas.setFillColor(GRAY)
    canvas.drawString(48,26,f'SCP | Group {GID} | M1 design / baseline preparation | {CFG["prepared_on"]}')
    canvas.drawRightString(PAGE_W-48,26,str(doc.page))
    canvas.restoreState()

def parse(source):
    lines=source.splitlines(); result=[]; i=0
    while i<len(lines):
        line=lines[i].strip()
        if not line: i+=1; continue
        if line.startswith('# '): result.append(para(line[2:],'title')); i+=1
        elif line.startswith('## '): result.append(para(line[3:],'h2')); i+=1
        elif re.fullmatch(r'\{\{(TOPOLOGY|PKI|TLS|IKE|KERBEROS)\}\}',line):
            figure = [Spacer(1,8), Diagram(line[2:-2]), Spacer(1,10)]
            if result and isinstance(result[-1], Paragraph) and result[-1].style.name=='Heading2':
                figure.insert(0,result.pop())
            result.append(KeepTogether(figure)); i+=1
        elif line=='{{TEAM}}':
            rows=[['Student ID','Confirmed original name']]
            for m in CFG['members']:
                rows.append([m['student_id'],Paragraph(html.escape(arabic_visual(m['name'])),STYLES['name'])])
            result.append(table(rows,[WIDTH*.29,WIDTH*.71])); i+=1
        elif line=='{{SUBMISSION_LINKS}}':
            result.extend([submission_links(),Spacer(1,9)]); i+=1
        elif line=='{{BASELINE_SUMMARY}}':
            result.extend([baseline_table(),Spacer(1,9)]); i+=1
        elif line.startswith('|'):
            rows=[]
            while i<len(lines) and lines[i].strip().startswith('|'):
                row=[x.strip() for x in lines[i].strip().strip('|').split('|')]
                if not all(re.fullmatch(r'[-: ]+', x) for x in row): rows.append(row)
                i+=1
            if any(len(r)!=len(rows[0]) for r in rows):
                raise ValueError('Inconsistent table column count')
            # Let long tables split into the remaining first-page space instead
            # of moving the entire heading/table group to a mostly empty page.
            if result and isinstance(result[-1], Paragraph) and result[-1].style.name=='Heading2':
                heading=result.pop()
                heading.keepWithNext=False
                minimum=table(rows[:2]).wrap(WIDTH,10000)[1]+heading.wrap(WIDTH,10000)[1]+30
                result.extend([CondPageBreak(minimum),heading])
            result += [table(rows),Spacer(1,9)]
        else:
            parts=[line]; i+=1
            while i<len(lines) and lines[i].strip() and not lines[i].startswith(('#','|','{{')) and not re.match(r'^\d+\. ',lines[i]):
                parts.append(lines[i].strip()); i+=1
            result.append(para(' '.join(parts)))
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--only', choices=[p.stem for p in (ROOT/'docs/M1/source').glob('M1_*.md')])
    parser.add_argument('--submission',action='store_true',help='Combine the retained cover and six M1 PDFs with bookmarks')
    args=parser.parse_args()
    out=ROOT/'docs/M1'; out.mkdir(parents=True,exist_ok=True)
    for src in ([] if args.submission else sorted((out/'source').glob('M1_*.md'))):
        if args.only and src.stem!=args.only:
            continue
        dst=out/(src.stem+'.pdf')
        doc=SimpleDocTemplate(str(dst),pagesize=A4,rightMargin=48,leftMargin=48,topMargin=43,bottomMargin=54,
             title=f'{src.stem} - SCP Group {GID}',author='SCP Group '+GID, pageCompression=1)
        doc.build(parse(src.read_text(encoding='utf-8')),onFirstPage=footer,onLaterPages=footer)
        print(dst.name)
    if args.submission:
        from pypdf import PdfWriter
        temp=ROOT/'tmp/pdfs'; temp.mkdir(parents=True,exist_ok=True)
        cover=temp/'Submission_Cover.pdf'
        doc=SimpleDocTemplate(str(cover),pagesize=A4,rightMargin=48,leftMargin=48,topMargin=43,bottomMargin=54,
              title='M1 Submission Package - Group '+GID,author='SCP Group '+GID)
        doc.build(parse((out/'source/Submission_Cover.md').read_text(encoding='utf-8')),onFirstPage=footer,onLaterPages=footer)
        writer=PdfWriter()
        writer.append(str(cover),outline_item='Submission, repository and baseline evidence')
        sections=[('M1_Requirements','Requirements and acceptance'),('M1_Topology_Trust','Topology and trust boundaries'),
             ('M1_PKI_Design','PKI design'),('M1_ProtocolDesign','Protocol design'),('M1_STRIDE','STRIDE threats'),('M1_TeamPlan','Team and release plan')]
        for name,title in sections: writer.append(str(out/(name+'.pdf')),outline_item=title)
        writer.add_metadata({'/Title':'Secure Inter-Campus Communication Network - M1 - Group '+GID,'/Author':'SCP Group '+GID})
        with open(out/'M1_Submission.pdf','wb') as output: writer.write(output)
        print('M1_Submission.pdf')

if __name__=='__main__':
    main()
