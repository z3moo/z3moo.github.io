export type Site = {
  TITLE: string
  DESCRIPTION: string
  EMAIL: string
  NUM_POSTS_ON_HOMEPAGE: number
  POSTS_PER_PAGE: number
  SITEURL: string
}

export type Link = {
  href: string
  label: string
}

export const SITE: Site = {
  TITLE: 'pacho',
  DESCRIPTION:
    'A blog about my life, work, and the journey studying information security.',
  EMAIL: 'danhquan2005@gmail.com',
  NUM_POSTS_ON_HOMEPAGE: 3,
  POSTS_PER_PAGE: 3,
  SITEURL: 'https://z3moo.github.io',
}

export const NAV_LINKS: Link[] = [
  { href: '/', label: 'home' },
  { href: '/blog', label: 'blog' },
  { href: '/work', label: 'work' },
  { href: '/certification', label: 'certification' },
]

export const SOCIAL_LINKS: Link[] = [
  { href: 'https://github.com/z3moo', label: 'GitHub' },
  { href: 'danhquan2005@gmail.com', label: 'Email' },
  { href: '/rss.xml', label: 'RSS' },
]
