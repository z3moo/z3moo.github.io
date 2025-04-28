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
  TITLE: 'Emile Choghi',
  DESCRIPTION:
    'Emile Choghi is a software engineer who specializes in building useful digital experiences.',
  EMAIL: 'echoghi@rennalabs.xyz',
  NUM_POSTS_ON_HOMEPAGE: 3,
  POSTS_PER_PAGE: 3,
  SITEURL: 'https://z3moo.github.io',
}

export const NAV_LINKS: Link[] = [
  { href: '/', label: 'home' },
  { href: '/blog', label: 'blog' },
  { href: '/work', label: 'work' },
]

export const SOCIAL_LINKS: Link[] = [
  { href: 'https://github.com/echoghi', label: 'GitHub' },
  { href: 'echoghi@rennalabs.xyz', label: 'Email' },
  { href: '/rss.xml', label: 'RSS' },
]
