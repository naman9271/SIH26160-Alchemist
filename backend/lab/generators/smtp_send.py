import argparse, email.message, os, random, smtplib, time
p=argparse.ArgumentParser(); p.add_argument('host'); p.add_argument('--count',type=int,required=True); p.add_argument('--seed',type=int,required=True); a=p.parse_args(); r=random.Random(a.seed)
for i in range(a.count):
 m=email.message.EmailMessage(); m['From']='sender@lab.test'; m['To']='receiver@lab.test'; m['Subject']=f'Lab message {i}'
 m.set_content(' '.join(['controlled']*r.randint(30,2500)))
 if r.random()<.55: m.add_attachment(os.urandom(r.randint(10_000,300_000)),maintype='application',subtype='octet-stream',filename=f'attachment-{i}.bin')
 with smtplib.SMTP(a.host,2525,timeout=20) as s: s.send_message(m)
 time.sleep(r.uniform(.08,.7))
