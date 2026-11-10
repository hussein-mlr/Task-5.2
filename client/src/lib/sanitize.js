import DOMPurify from 'dompurify'

// Reviews are rendered as HTML so people can use light formatting (bold, links).
// This helper is the single place review HTML passes through before it is handed
// to React's dangerouslySetInnerHTML (components/ReviewList.jsx), so it is the one
// spot responsible for turning untrusted, attacker-controlled markup into safe markup.
//
// We SANITIZE (keep a small allow-list of harmless formatting, drop everything else)
// instead of ESCAPING (showing every tag as literal text), because reviewers are
// supposed to be able to use <b>, links, lists, etc. DOMPurify parses the HTML the
// same way the browser will, so tricks that fool regex-based filters don't work.

// Only these tags survive. Everything else (<script>, <img>, <svg>, <iframe>, <style>,
// <form>, <object>, ...) is removed. <script>/<style> lose their contents too; for any
// other removed tag the plain text inside is kept.
const ALLOWED_TAGS = [
  'b', 'strong', 'i', 'em', 'u', 's',
  'p', 'br', 'ul', 'ol', 'li',
  'blockquote', 'code', 'pre',
  'a'
]

// Only these attributes survive, so every inline event handler (onerror, onload,
// onclick, ...), style, id/name (DOM clobbering) and data-* attributes are dropped.
const ALLOWED_ATTR = ['href', 'title']

// Links may only point to http(s) or mailto. This drops javascript:, data:, vbscript:
// and anything else (DOMPurify strips whitespace/control chars before checking, so
// "java\tscript:" doesn't slip through).
const ALLOWED_URI_REGEXP = /^(?:https?:|mailto:)/i

const CONFIG = {
  ALLOWED_TAGS,
  ALLOWED_ATTR,
  ALLOWED_URI_REGEXP,
  ALLOW_DATA_ATTR: false
}

// A private DOMPurify instance, so the hook below doesn't leak into any other code
// that might use the shared default instance.
const purifier = DOMPurify(window)

// Links in user content open in a new tab without giving the new page a handle on
// ours (rel=noopener prevents reverse-tabnabbing) and without passing SEO credit.
// The hook runs after attribute filtering, so these values are ours, not the user's.
purifier.addHook('afterSanitizeAttributes', (node) => {
  if (node.tagName === 'A' && node.hasAttribute('href')) {
    node.setAttribute('target', '_blank')
    node.setAttribute('rel', 'noopener noreferrer nofollow')
  }
})

export function sanitizeHtml(dirty) {
  if (typeof dirty !== 'string' || dirty === '') return ''
  return purifier.sanitize(dirty, CONFIG)
}
