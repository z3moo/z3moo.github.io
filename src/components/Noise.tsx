import * as React from 'react'
import { Slider } from '@/components/ui/slider'
import { Switch } from '@/components/ui/switch'
import { Label } from '@/components/ui/label'
import { cn } from '@/lib/utils'

interface NoiseOverlayProps {
  image: string
  className?: string
}

export function NoiseOverlay({ image, className = '' }: NoiseOverlayProps) {
  const [baseFrequency, setBaseFrequency] = React.useState(0.75)
  const [opacity, setOpacity] = React.useState(0.3)
  const [noiseEnabled, setNoiseEnabled] = React.useState(true)

  const handleFrequencyChange = React.useCallback((value: number[]) => {
    setBaseFrequency(value[0])
  }, [])

  const handleOpacityChange = React.useCallback((value: number[]) => {
    setOpacity(value[0])
  }, [])

  const handleNoiseToggle = React.useCallback((checked: boolean) => {
    setNoiseEnabled(checked)
  }, [])

  const noiseSvg = `data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='100%25' height='100%25'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='${baseFrequency}' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)' opacity='${opacity}'/%3E%3C/svg%3E`

  return (
    <div>
      <div className={cn('relative mb-8', className)}>
        <img src={image} alt="Base image" className="mb-1 h-full w-full" />
        {noiseEnabled && (
          <div
            className="absolute inset-0"
            style={{
              background: `url("${noiseSvg}")`,
              pointerEvents: 'none',
            }}
          />
        )}
      </div>

      <div className="space-y-4">
        <div className="flex items-center space-x-2">
          <Switch
            id="noise-toggle"
            checked={noiseEnabled}
            onCheckedChange={handleNoiseToggle}
          />
          <Label htmlFor="noise-toggle">Noise Overlay</Label>
        </div>

        <div className="space-y-2">
          <Label>Base Frequency: {baseFrequency.toFixed(2)}</Label>
          <Slider
            defaultValue={[baseFrequency]}
            onValueChange={handleFrequencyChange}
            min={0.1}
            max={2}
            step={0.05}
            disabled={!noiseEnabled}
          />
        </div>

        <div className="space-y-2">
          <Label>Opacity: {opacity.toFixed(2)}</Label>
          <Slider
            defaultValue={[opacity]}
            onValueChange={handleOpacityChange}
            min={0}
            max={1}
            step={0.05}
            disabled={!noiseEnabled}
          />
        </div>
      </div>
    </div>
  )
}
