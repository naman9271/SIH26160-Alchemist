"use client";

import { useEffect, useRef } from "react";

type GatewayFlowProps = {
  className?: string;
  density?: number;
  opacity?: number;
  speed?: number;
};

/** Animated protocol paths adapted from the supplied Gateway Flow component. */
export default function GatewayFlow({
  className,
  density = 0.45,
  opacity = 0.42,
  speed = 0.65,
}: GatewayFlowProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const context = canvas?.getContext("2d");
    if (!canvas || !context) return;

    let frameId = 0;
    let width = 0;
    let height = 0;
    const pathCount = Math.max(12, Math.round(80 * density));
    const paths = Array.from({ length: pathCount }, (_, index) => ({
      isLeft: index % 2 === 0,
      startY: 0,
      progress: Math.random(),
      particleSpeed: (0.0015 + Math.random() * 0.002) * speed,
    }));

    const resize = () => {
      const bounds = canvas.getBoundingClientRect();
      const pixelRatio = Math.min(window.devicePixelRatio || 1, 2);
      width = bounds.width;
      height = bounds.height;
      canvas.width = Math.round(width * pixelRatio);
      canvas.height = Math.round(height * pixelRatio);
      context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
      paths.forEach((path, index) => {
        path.startY = (index / pathCount) * height * 1.4 - height * 0.2;
      });
    };

    const pointAt = (progress: number, p0: Point, p1: Point, p2: Point, p3: Point) => {
      const inverse = 1 - progress;
      return {
        x: inverse ** 3 * p0.x + 3 * inverse ** 2 * progress * p1.x + 3 * inverse * progress ** 2 * p2.x + progress ** 3 * p3.x,
        y: inverse ** 3 * p0.y + 3 * inverse ** 2 * progress * p1.y + 3 * inverse * progress ** 2 * p2.y + progress ** 3 * p3.y,
      };
    };

    const draw = () => {
      context.clearRect(0, 0, width, height);
      const centerX = width / 2;
      const centerY = height / 2;
      paths.forEach((path) => {
        const p0 = { x: path.isLeft ? 0 : width, y: path.startY };
        const p1 = { x: path.isLeft ? centerX * 0.5 : width - centerX * 0.5, y: path.startY };
        const p2 = { x: path.isLeft ? centerX * 0.8 : width - centerX * 0.8, y: centerY };
        const p3 = { x: centerX, y: centerY };
        context.beginPath();
        context.moveTo(p0.x, p0.y);
        context.bezierCurveTo(p1.x, p1.y, p2.x, p2.y, p3.x, p3.y);
        context.setLineDash([2, 7]);
        context.strokeStyle = `rgba(165, 180, 252, ${opacity * 0.72})`;
        context.lineWidth = 1.8;
        context.stroke();
        context.setLineDash([]);
        path.progress += path.particleSpeed;
        if (path.progress > 1) path.progress = 0;
        const point = pointAt(path.progress, p0, p1, p2, p3);
        context.fillStyle = `rgba(219, 234, 254, ${opacity})`;
        context.shadowBlur = 12;
        context.shadowColor = "#818cf8";
        context.fillRect(point.x - 2, point.y - 2, 4, 4);
        context.shadowBlur = 0;
      });
      frameId = requestAnimationFrame(draw);
    };

    const observer = new ResizeObserver(resize);
    observer.observe(canvas);
    resize();
    draw();
    return () => {
      observer.disconnect();
      cancelAnimationFrame(frameId);
    };
  }, [density, opacity, speed]);

  return <canvas ref={canvasRef} aria-hidden="true" className={className} />;
}

type Point = { x: number; y: number };
