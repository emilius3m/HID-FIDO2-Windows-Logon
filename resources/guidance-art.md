# Wizard illustrations

`guidance-atlas.png` is a generated transparent PNG, embedded as resource
1100 in the native manager and vault helper. It adds no runtime file to the
four-payload distribution. The application selects an equal-size quadrant:
insert, remove, touch, release. Devices are generic instructional examples.

Created with the built-in image generation tool from the approved UI
storyboard. Final prompt:

> Create a transparent four-cell 2×2 illustration atlas. Preserve the clear
> black/gray outlines and small blue accents of the approved hardware
> drawings. Remove all window chrome, text, labels, numbers and buttons.
> Top left: USB key moving into a laptop port, arrow toward the port. Top
> right: same key and port, arrow away for unplugging. Bottom left: a finger
> touching the key sensor. Bottom right: the finger visibly lifted above the
> sensor, with an upward arrow. Use consistent scale, stroke and equal cell
> placement, with transparent padding. No captions, borders or watermark.

The PNG is included in the project; compilation needs no image-generation
service. The shared renderer retains a native vector fallback if decoding
fails, and illustrations never determine hardware state or authorization.
