import fs from 'fs'
import path from 'path'
import sharp from 'sharp'
import { join } from 'path'
import { imageSizeFromFile } from 'image-size/fromFile'
import { getEntry } from 'astro:content'

import type { ImageMetadata } from 'astro'

export async function parseAuthors(authors: string[]) {
  if (!authors || authors.length === 0) return []

  const parseAuthor = async (id: string) => {
    try {
      const author = await getEntry('authors', id)
      return {
        id,
        name: author?.data?.name || id,
        avatar: author?.data?.avatar || '/static/logo.png',
        isRegistered: !!author,
      }
    } catch (error) {
      console.error(`Error fetching author with id ${id}:`, error)
      return {
        id,
        name: id,
        avatar: '/static/logo.png',
        isRegistered: false,
      }
    }
  }

  return await Promise.all(authors.map(parseAuthor))
}

export async function getPhotoCount(albumId: string): Promise<number> {
  const publicDir = path.join(process.cwd(), 'public', 'images', albumId)

  try {
    const files = fs.readdirSync(publicDir)
    const webpFiles = files.filter((file) => file.endsWith('.webp'))
    return webpFiles.length
  } catch (error) {
    console.error('Error counting photos:', error)
    return 0
  }
}

interface FullSizeImage extends ImageMetadata {
  src: string
  hash: string
  width: number
  height: number
  blurDataUrl: string
}

/**
 * Generates a base64 WebP data URI from an image file to use as a blurred placeholder.
 */
export async function generateBlurPlaceholder(
  imagePath: string,
  blurSize = 32,
  blurSigma = 2.5,
): Promise<string | undefined> {
  try {
    const { data, info } = await sharp(imagePath)
      .resize(blurSize, blurSize, { fit: 'inside' })
      .blur(blurSigma)
      .raw()
      .ensureAlpha()
      .toBuffer({ resolveWithObject: true })

    const webpBuffer = await sharp(data, {
      raw: {
        width: info.width,
        height: info.height,
        channels: 4,
      },
    })
      .webp({ quality: 60 })
      .toBuffer()

    return `data:image/webp;base64,${webpBuffer.toString('base64')}`
  } catch (err) {
    console.warn(
      `Failed to generate blurred placeholder for ${imagePath}:`,
      err,
    )
    return undefined
  }
}

/**
 * Resolves and returns metadata for full-size images, including dimensions and blur assets.
 */
export async function getFullSizeImages(
  images: ImageMetadata[],
  id: string,
): Promise<FullSizeImage[]> {
  return await Promise.all(
    images.map(async (img) => {
      const fileName = img.src.split('/').pop()
      if (!fileName) return img as FullSizeImage

      const cleanedFileName = fileName
        .replace('-preview', '')
        .split('?')[0]
        .replace(/\.(jpe?g|png)$/i, '.webp')
        .replace(/(\.[^.]+\.webp)$/, (match) => {
          const parts = match.split('.')
          return `${parts[0]}.webp`
        })

      const hash = fileName.replace('-preview', '').split('?')[0].split('.')[0]

      const fullSizePath = join(
        process.cwd(),
        'public',
        'images',
        id,
        cleanedFileName,
      )
      let width = img.width
      let height = img.height
      let blurDataUrl: string | undefined

      if (fs.existsSync(fullSizePath)) {
        try {
          const dimensions = await imageSizeFromFile(fullSizePath)
          if (dimensions.width && dimensions.height) {
            width = dimensions.width
            height = dimensions.height
          }

          blurDataUrl = await generateBlurPlaceholder(fullSizePath)
        } catch (err) {
          console.warn(`Error processing ${fullSizePath}:`, err)
        }
      } else {
        console.warn(`Full-size image not found: ${fullSizePath}`)
      }

      return {
        ...img,
        src: `/images/${id}/${cleanedFileName}`,
        width,
        height,
        hash,
        blurDataUrl: blurDataUrl || '',
      }
    }),
  )
}
