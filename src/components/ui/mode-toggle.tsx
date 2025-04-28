import * as React from 'react'

export function ModeToggle() {
  React.useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')

    function applySystemMode() {
      // Determine if system is in dark mode
      const isDark = mediaQuery.matches

      // Temporarily disable transitions
      document.documentElement.classList.add('disable-transitions')

      // Apply/remove the `.dark` class
      document.documentElement.classList[isDark ? 'add' : 'remove']('dark')

      // Force the browser to recalc style for the animation trick
      window
        .getComputedStyle(document.documentElement)
        .getPropertyValue('opacity')

      // Re-enable transitions on next animation frame
      requestAnimationFrame(() => {
        document.documentElement.classList.remove('disable-transitions')
      })
    }

    // Apply preference on load
    applySystemMode()

    // Watch for system preference changes
    mediaQuery.addEventListener('change', applySystemMode)
    return () => {
      mediaQuery.removeEventListener('change', applySystemMode)
    }
  }, [])

  // Return nothing (or any small UI element if you want)
  return null
}
