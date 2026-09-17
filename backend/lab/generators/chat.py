import argparse, asyncio, os, random, websockets
p=argparse.ArgumentParser(); p.add_argument('mode',choices=['server','client']); p.add_argument('--host',default='0.0.0.0'); p.add_argument('--count',type=int,default=100); p.add_argument('--duration',type=float,default=60); p.add_argument('--seed',type=int,default=1); a=p.parse_args()
async def server():
 async def handler(ws, path=None):
  async for message in ws: await ws.send(message[::-1] if isinstance(message,bytes) else 'ack:'+message)
 async with websockets.serve(handler,a.host,8765): await asyncio.Future()
async def client():
 r=random.Random(a.seed)
 host = f'[{a.host}]' if ':' in a.host and not a.host.startswith('[') else a.host
 async with websockets.connect(f'ws://{host}:8765') as ws:
  for i in range(a.count):
   payload=os.urandom(r.randint(800,6000)) if r.random()<.07 else ('message-%s-'%i)*r.randint(1,20)
   await ws.send(payload); await ws.recv()
   # Keep every chat run in the requested 45--90 second range regardless of
   # its independently selected message count.
   await asyncio.sleep(r.uniform(.75,1.25) * a.duration / a.count)
asyncio.run(server() if a.mode=='server' else client())
