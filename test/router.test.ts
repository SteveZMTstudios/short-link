import { describe, it, expect } from 'vitest';
import {
  matchesPattern,
  findMatchingRoute,
  getRouteSpecificity,
  normalizePattern,
} from '../src/router/matcher';
import { RouteDefinition } from '../src/types';

describe('Router & Pattern Matcher', () => {
  it('matches simple subpath patterns', () => {
    const url = new URL('https://example.com/github');
    expect(matchesPattern('/github', url)).toBe(true);
    expect(matchesPattern('/other', url)).toBe(false);
  });

  it('matches wildcard subpaths', () => {
    const url = new URL('https://example.com/blog/2026/hello');
    expect(matchesPattern('/blog/*', url)).toBe(true);
    expect(matchesPattern('/news/*', url)).toBe(false);
  });

  it('matches exact host and path', () => {
    const url = new URL('https://s.stevezmt.top/blog/post-1');
    expect(matchesPattern('s.stevezmt.top/blog/*', url)).toBe(true);
    expect(matchesPattern('other.stevezmt.top/blog/*', url)).toBe(false);
  });

  it('matches wildcard subdomains', () => {
    const url = new URL('https://sub.stevezmt.top/test');
    expect(matchesPattern('*.stevezmt.top/*', url)).toBe(true);
  });

  it('respects route specificity ordering', () => {
    const routes: RouteDefinition[] = [
      { pattern: '/*/*', target: 'https://catchall.com' },
      { pattern: 's.stevezmt.top/blog/*', target: 'https://specific-subdomain.com' },
      { pattern: '/blog/featured', target: 'https://exact-featured.com' },
    ];

    const urlSpecific = new URL('https://s.stevezmt.top/blog/my-post');
    const matched = findMatchingRoute(routes, urlSpecific);
    expect(matched?.target).toBe('https://specific-subdomain.com');

    const urlExact = new URL('https://example.com/blog/featured');
    const matchedExact = findMatchingRoute(routes, urlExact);
    expect(matchedExact?.target).toBe('https://exact-featured.com');
  });

  it('ensures exact literal route always beats parameterized route (e.g. /a vs /:slug)', () => {
    const routes: RouteDefinition[] = [
      { pattern: '/:slug', target: 'https://param-target.com/:slug' },
      { pattern: '/a', target: 'https://exact-target.com/a' },
      { pattern: '/*', target: 'https://wildcard-target.com/*' },
    ];

    const urlA = new URL('https://example.com/a');
    const matchA = findMatchingRoute(routes, urlA);
    expect(matchA?.target).toBe('https://exact-target.com/a');

    const urlOther = new URL('https://example.com/other');
    const matchOther = findMatchingRoute(routes, urlOther);
    expect(matchOther?.target).toBe('https://param-target.com/:slug');
    expect(matchOther?.params.slug).toBe('other');
  });

  it('tolerates trailing slashes seamlessly (/github and /github/ both match)', () => {
    const urlWithoutSlash = new URL('https://example.com/github');
    const urlWithSlash = new URL('https://example.com/github/');

    expect(matchesPattern('/github', urlWithoutSlash)).toBe(true);
    expect(matchesPattern('/github', urlWithSlash)).toBe(true);

    const routes: RouteDefinition[] = [{ pattern: '/docs', target: 'https://example.com/docs' }];
    const matchWithSlash = findMatchingRoute(routes, new URL('https://example.com/docs/'));
    expect(matchWithSlash).not.toBeNull();
    expect(matchWithSlash?.target).toBe('https://example.com/docs');
  });

  it('safely normalizes top-level parameter routes (/:slug) without corrupting them into subdomains', () => {
    // /:slug should NOT become /.stevezmt.top/slug
    expect(normalizePattern('/:slug', 'stevezmt.top')).toBe('/:slug');
    expect(normalizePattern('/api/:version/:id', 'stevezmt.top')).toBe('/api/:version/:id');

    // Valid subdomains should still expand
    expect(normalizePattern('blog:/:slug', 'stevezmt.top')).toBe('blog.stevezmt.top/:slug');
    expect(normalizePattern('s:/link', 'stevezmt.top')).toBe('s.stevezmt.top/link');
  });

  it('guarantees specificity hierarchy: Exact > Param > Wildcard > Regex', () => {
    const exactScore = getRouteSpecificity('/blog/post');
    const paramScore = getRouteSpecificity('/blog/:slug');
    const wildcardScore = getRouteSpecificity('/blog/*');
    const regexScore = getRouteSpecificity('regex:^/blog/.*$');

    expect(exactScore).toBeGreaterThan(paramScore);
    expect(paramScore).toBeGreaterThan(wildcardScore);
    expect(wildcardScore).toBeGreaterThan(regexScore);
  });
});
