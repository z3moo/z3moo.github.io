import { useState, useMemo } from 'react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
  DropdownMenuLabel,
  DropdownMenuSeparator,
} from '@/components/ui/dropdown-menu'
import { ChevronDown, Filter, ArrowUpDown, ArrowRight, Zap, Calendar } from 'lucide-react'

type HTBItem = {
  id: string
  data: {
    title: string
    issuer: string
    status: string
    difficulty?: 'Very Easy' | 'Easy' | 'Medium' | 'Hard' | 'Insane'
    date: string
    description?: string
    badge?: string | null
    certificateLink?: string | null
    tags?: string[]
  }
}

type HTBFilterProps = {
  items: HTBItem[]
}

const difficultyOrder = {
  'Very Easy': 1,
  'Easy': 2,
  'Medium': 3,
  'Hard': 4,
  'Insane': 5,
}

export default function HTBFilter({ items }: HTBFilterProps) {
  const [selectedDifficulty, setSelectedDifficulty] = useState<string>('all')
  const [sortBy, setSortBy] = useState<string>('date-desc')

  const difficulties = useMemo(() => {
    const diffs = new Set<string>()
    items.forEach((item) => {
      if (item.data.difficulty) {
        diffs.add(item.data.difficulty)
      }
    })
    return Array.from(diffs).sort(
      (a, b) => difficultyOrder[a as keyof typeof difficultyOrder] - difficultyOrder[b as keyof typeof difficultyOrder]
    )
  }, [items])

  const filteredAndSortedItems = useMemo(() => {
    let result = [...items]

    // Filter by difficulty
    if (selectedDifficulty !== 'all') {
      result = result.filter((item) => item.data.difficulty === selectedDifficulty)
    }

    // Sort
    result.sort((a, b) => {
      switch (sortBy) {
        case 'date-desc':
          return new Date(b.data.date).getTime() - new Date(a.data.date).getTime()
        case 'date-asc':
          return new Date(a.data.date).getTime() - new Date(b.data.date).getTime()
        case 'difficulty-asc': {
          const diffA = a.data.difficulty ? difficultyOrder[a.data.difficulty] : 0
          const diffB = b.data.difficulty ? difficultyOrder[b.data.difficulty] : 0
          return diffA - diffB
        }
        case 'difficulty-desc': {
          const diffA = a.data.difficulty ? difficultyOrder[a.data.difficulty] : 0
          const diffB = b.data.difficulty ? difficultyOrder[b.data.difficulty] : 0
          return diffB - diffA
        }
        case 'title-asc':
          return a.data.title.localeCompare(b.data.title)
        case 'title-desc':
          return b.data.title.localeCompare(a.data.title)
        default:
          return 0
      }
    })

    return result
  }, [items, selectedDifficulty, sortBy])

  return (
    <div>
      {/* Filters and Sort Controls */}
      <div className="mb-6 flex flex-wrap gap-3 items-center">
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium">Filter:</span>
        </div>
        
        {/* Difficulty Filter */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" size="sm" className="gap-2">
              {selectedDifficulty === 'all' ? 'All Difficulties' : selectedDifficulty}
              <ChevronDown className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start">
            <DropdownMenuLabel>Difficulty</DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuRadioGroup value={selectedDifficulty} onValueChange={setSelectedDifficulty}>
              <DropdownMenuRadioItem value="all">All Difficulties</DropdownMenuRadioItem>
              {difficulties.map((diff) => (
                <DropdownMenuRadioItem key={diff} value={diff}>
                  {diff}
                </DropdownMenuRadioItem>
              ))}
            </DropdownMenuRadioGroup>
          </DropdownMenuContent>
        </DropdownMenu>

        {/* Sort By */}
        <div className="flex items-center gap-2 ml-auto">
          <ArrowUpDown className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium">Sort:</span>
        </div>
        
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" size="sm" className="gap-2">
              {sortBy === 'date-desc' && 'Newest First'}
              {sortBy === 'date-asc' && 'Oldest First'}
              {sortBy === 'difficulty-asc' && 'Easiest First'}
              {sortBy === 'difficulty-desc' && 'Hardest First'}
              {sortBy === 'title-asc' && 'Title A-Z'}
              {sortBy === 'title-desc' && 'Title Z-A'}
              <ChevronDown className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuLabel>Sort By</DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuRadioGroup value={sortBy} onValueChange={setSortBy}>
              <DropdownMenuRadioItem value="date-desc">Newest First</DropdownMenuRadioItem>
              <DropdownMenuRadioItem value="date-asc">Oldest First</DropdownMenuRadioItem>
              <DropdownMenuRadioItem value="difficulty-asc">Easiest First</DropdownMenuRadioItem>
              <DropdownMenuRadioItem value="difficulty-desc">Hardest First</DropdownMenuRadioItem>
              <DropdownMenuRadioItem value="title-asc">Title A-Z</DropdownMenuRadioItem>
              <DropdownMenuRadioItem value="title-desc">Title Z-A</DropdownMenuRadioItem>
            </DropdownMenuRadioGroup>
          </DropdownMenuContent>
        </DropdownMenu>

        {/* Active Filter Display */}
        {selectedDifficulty !== 'all' && (
          <Badge 
            variant="secondary" 
            className="gap-1 cursor-pointer hover:bg-secondary/80"
            onClick={() => setSelectedDifficulty('all')}
          >
            {selectedDifficulty}
            <span className="text-xs">✕</span>
          </Badge>
        )}
      </div>

      {/* Results Count */}
      <div className="mb-4 text-sm text-muted-foreground">
        Showing {filteredAndSortedItems.length} of {items.length} {filteredAndSortedItems.length === 1 ? 'item' : 'items'}
      </div>

      {/* Render filtered items */}
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-2">
        {filteredAndSortedItems.map((item) => (
          <a key={item.id} href={`/htb/${item.id}`} className="block group">
            <Card className="h-full transition-all duration-200 group-hover:shadow-lg group-hover:scale-[1.02]">
              <CardHeader className="pb-4">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <h3 className="text-lg font-semibold group-hover:text-primary transition-colors">{item.data.title}</h3>
                    <p className="text-sm text-muted-foreground">{item.data.issuer}</p>
                  </div>
                  {item.data.badge && (
                    <img 
                      src={item.data.badge} 
                      alt={`${item.data.title} badge`}
                      className="h-12 w-12 object-contain"
                    />
                  )}
                </div>
                <div className="flex gap-2 flex-wrap">
                  <Badge variant={item.data.status === 'Completed' ? 'default' : 'secondary'}>
                    {item.data.status}
                  </Badge>
                  {item.data.difficulty && (
                    <Badge variant="outline" className="gap-1">
                      <Zap className="h-3 w-3" />
                      {item.data.difficulty}
                    </Badge>
                  )}
                  <Badge variant="outline" className="gap-1">
                    <Calendar className="h-3 w-3" />
                    {item.data.date}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent>
                {item.data.description && (
                  <p className="text-sm text-muted-foreground mb-4">
                    {item.data.description}
                  </p>
                )}
                <div className="flex items-center justify-between">
                  <span className="text-sm text-primary font-medium group-hover:underline">
                    Read more
                  </span>
                  <ArrowRight className="h-4 w-4 text-muted-foreground group-hover:text-primary group-hover:translate-x-1 transition-all" />
                </div>
              </CardContent>
            </Card>
          </a>
        ))}
      </div>
    </div>
  )
}
