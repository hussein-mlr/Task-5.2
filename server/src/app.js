import express from 'express';
import helmet from 'helmet';
import morgan from 'morgan';
import cors from 'cors';
import authRoutes from './routes/auth.js';
import listingRoutes from './routes/listings.js';
import userRoutes from './routes/users.js';
import reviewRoutes from './routes/reviews.js';

const app = express();

// Security headers. The one that matters for the Reviews feature is the
// Content-Security-Policy: a browser-enforced allow-list of what a page may load
// and execute. It is the second, independent layer behind DOMPurify on the client
// (defense-in-depth): if hostile markup ever reaches the DOM anyway (a sanitizer
// bug or bypass, a new code path that forgets to sanitize), the browser still
// refuses to run inline/injected JavaScript or send data to another origin.
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false, // spell out every directive instead of inheriting helmet's looser defaults
      directives: {
        defaultSrc: ["'self'"],
        // Only script files from our own origin. No 'unsafe-inline' (inline <script> blocks and
        // javascript: URLs) and no 'unsafe-eval' (eval/new Function).
        scriptSrc: ["'self'"],
        // Never run inline event-handler attributes — exactly what <img src=x onerror=...> uses.
        scriptSrcAttr: ["'none'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        // fetch/XHR/WebSocket may only talk to us, so a script that did run couldn't ship a
        // stolen token to attacker.example.
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"], // no <object>/<embed> plugins
        baseUri: ["'self'"], // an injected <base href> can't re-point our relative URLs
        formAction: ["'self'"], // an injected <form> can't post to another site
        frameAncestors: ["'none'"] // nobody may frame us (clickjacking)
      }
    }
  })
);

app.use(morgan('dev'));
app.use(cors({ origin: 'http://localhost:5175', credentials: false }));
app.use(express.json());

app.get('/api/health', (req, res) => res.json({ ok: true }));

app.use('/api/auth', authRoutes);
app.use('/api/listings', listingRoutes);
app.use('/api/users', userRoutes);
app.use('/api/reviews', reviewRoutes);

// Not found
app.use((req, res) => {
  res.status(404).json({ message: 'Not Found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ message: err.message || 'Server Error' });
});

export default app;
