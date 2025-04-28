A personal blog and portfolio website built with [Astro](https://astro.build/), [React](https://reactjs.org/), and [Tailwind CSS](https://tailwindcss.com/).

## 🚀 Features

- 📝 Blog with Markdown/MDX support
- 🧮 LaTeX math rendering with KaTeX
- 🎨 Beautiful code syntax highlighting with rehype-pretty-code
- 📱 Fully responsive design
- 🌙 Dark/light mode toggle
- 🖼️ Image optimization
- 🔍 SEO friendly
- 📊 RSS feed
- 🌐 Sitemap generation
- 📁 Project showcase

## 📋 Prerequisites

- [Node.js](https://nodejs.org/) (v18 or higher)
- [npm](https://www.npmjs.com/) or [yarn](https://yarnpkg.com/)

## 🛠️ Setup & Development

1. Clone the repository:

```bash
git clone https://github.com/z3moo/z3moo.github.io.git
cd z3moo.github.io
```

2. Install dependencies:

```bash
npm install
# or
yarn
```

3. Start the development server:

```bash
npm run dev
# or
yarn dev
```

4. Open your browser and visit `http://localhost:1234`

## 📦 Building for Production

```bash
npm run build
# or
yarn build
```

This will generate the static site in the `dist` directory.

## 🧰 Available Scripts

- `npm run dev` - Start the development server
- `npm run build` - Build the site for production
- `npm run preview` - Preview the built site
- `npm run fonts` - Process fonts (runs the `process-fonts.sh` script)
- `npm run prettier` - Format code using Prettier
- `npm run resize-images` - Resize images for optimization

## 📚 Project Structure

```
/
├── public/               # Static assets (fonts, images)
├── src/
│   ├── assets/           # Images and other assets
│   ├── components/       # UI components
│   ├── content/          # Blog posts and author data
│   │   ├── authors/      # Author information
│   │   └── blog/         # Blog posts in Markdown/MDX
│   ├── layouts/          # Page layouts
│   ├── lib/              # Utility functions
│   ├── pages/            # Page routes
│   └── styles/           # CSS styles
└── package.json          # Project dependencies
```

## 🎨 Customization

Update site configuration values in `src/consts.ts` to change site title, description, and other global settings.

## 🧩 Technologies Used

- [Astro](https://astro.build/) - Web framework
- [React](https://reactjs.org/) - UI components
- [Tailwind CSS](https://tailwindcss.com/) - Styling
- [Shadcn UI](https://ui.shadcn.com/) - UI components
- [MDX](https://mdxjs.com/) - Enhanced Markdown
- [Rehype/Remark](https://github.com/rehypejs/rehype) - Markdown processing
- [KaTeX](https://katex.org/) - Math rendering

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- [Astro](https://astro.build/) for the fantastic web framework
- [Tailwind CSS](https://tailwindcss.com/) for the utility-first CSS framework
- [Emelia](https://github.com/echoghi) for the original web design inspiration
- [Flexoki](https://stephango.com/flexoki) color scheme for visual styling
