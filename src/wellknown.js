'use strict';

/**
 * Paths that are commonly left readable by mistake.
 *
 * The list is used by the offline provider and by the well-known path check.
 * It is a plain list of read-only requests: nothing here writes, deletes or
 * authenticates.
 */

const DEFAULT_WELL_KNOWN_PATHS = Object.freeze([
  '/robots.txt',
  '/sitemap.xml',
  '/.env',
  '/.git/config',
  '/.git/HEAD',
  '/.gitignore',
  '/.DS_Store',
  '/backup.zip',
  '/backup.sql',
  '/dump.sql',
  '/config.json',
  '/config.yaml',
  '/config.php.bak',
  '/wp-config.php.bak',
  '/.htaccess',
  '/.htpasswd',
  '/server-status',
  '/phpinfo.php',
  '/.well-known/security.txt',
]);

module.exports = {
  DEFAULT_WELL_KNOWN_PATHS,
};
