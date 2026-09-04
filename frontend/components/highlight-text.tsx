type HighlightTextProps = {
  title: string;
  highlight: string;
  className?: string;
};

/** Renders a title with a separately animatable highlighted phrase. */
export function HighlightText({ title, highlight, className }: HighlightTextProps) {
  const [before, ...after] = title.split(highlight);

  if (!after.length) {
    return <>{title}</>;
  }

  return (
    <span className={className}>
      {before}
      <span data-highlight-word className="relative z-0 inline-block whitespace-nowrap">
        <span
          aria-hidden="true"
          data-highlight-backdrop
          className="absolute -inset-x-[.1em] top-[.15em] bottom-[.1em] -z-10 origin-left bg-primary motion-safe:scale-x-0"
        />
        <span data-highlight-foreground className="motion-reduce:text-black">{highlight}</span>
      </span>
      {after.join(highlight)}
    </span>
  );
}
