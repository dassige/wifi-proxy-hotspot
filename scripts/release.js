#!/usr/bin/env node
/**
 * release.js — Generic Release Script
 *
 * Reads the current version from pyproject.toml, creates a Git tag,
 * pushes it to origin, and creates a GitHub Release.
 * The version is managed by the developer before running this script.
 *
 * Project-specific values (PROJECT_NAME, GITHUB_REPO) live in
 * release.config.js — edit that file to reuse this script elsewhere.
 *
 * Usage:
 *   node scripts/release.js
 */

'use strict';

const fs       = require('fs');
const path     = require('path');
const readline = require('readline');
const { execSync } = require('child_process');

const { PROJECT_NAME, GITHUB_REPO } = require('./release.config');

const ROOT           = path.resolve(__dirname, '..');
const PYPROJECT_PATH = path.join(ROOT, 'pyproject.toml');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function run(cmd) {
    return execSync(cmd, { cwd: ROOT, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
}

function tryRun(cmd) {
    try { return { ok: true, out: run(cmd) }; }
    catch (e) { return { ok: false, err: (e.stderr || e.message || '').trim() }; }
}

function ask(rl, question) {
    return new Promise(resolve => rl.question(question, resolve));
}

// This project versions itself in pyproject.toml's [project] version, not
// package.json (it's a Flask/Python deployment bundle, not an npm package)
// — a plain regex is enough here rather than pulling in a TOML parser.
function readProjectVersion() {
    const toml = fs.readFileSync(PYPROJECT_PATH, 'utf8');
    const m = toml.match(/^version\s*=\s*"([^"]+)"/m);
    if (!m) throw new Error(`Could not find a version = "..." line in ${PYPROJECT_PATH}`);
    return m[1];
}

function abort(rl, msg) {
    console.error(`\n✖  ${msg}`);
    if (rl) rl.close();
    process.exit(1);
}

function buildMarkdownNotes(commits, tagName, prevReleaseTag) {
    const TYPES = {
        feat:     { label: '✨ Features',       order: 1 },
        fix:      { label: '🐛 Bug Fixes',      order: 2 },
        perf:     { label: '⚡ Performance',     order: 3 },
        refactor: { label: '♻️ Refactoring',    order: 4 },
        docs:     { label: '📚 Documentation',  order: 5 },
        test:     { label: '🧪 Tests',           order: 6 },
        chore:    { label: '🔧 Maintenance',    order: 7 },
        ci:       { label: '⚙️ CI / CD',        order: 8 },
        build:    { label: '📦 Build',          order: 9 },
        revert:   { label: '⏪ Reverts',        order: 10 },
    };
    const OTHER_KEY   = 'other';
    const OTHER_LABEL = '🔀 Other Changes';

    // Parse one commit subject into its components.
    function parseSubject(subject) {
        // Matches: type(scope)!: description  OR  type!: description  OR  type: description
        const m = subject.match(/^([a-z]+)(?:\(([^)]*)\))?(!)?: (.+)/i);
        if (!m) return { type: OTHER_KEY, scope: null, breaking: false, desc: subject };
        return {
            type:     m[1].toLowerCase(),
            scope:    m[2] || null,
            breaking: !!m[3],
            desc:     m[4],
        };
    }

    // Format a bullet line: strip the type prefix; bold the scope if present.
    function formatBullet(subject) {
        const { scope, breaking, desc } = parseSubject(subject);
        const clean = desc.charAt(0).toUpperCase() + desc.slice(1);
        let bullet  = scope ? `**${scope}:** ${clean}` : clean;
        if (breaking) bullet = `⚠️ **Breaking:** ${bullet}`;
        return bullet;
    }

    const groups = {};
    for (const msg of commits) {
        const lines   = msg.split('\n');
        const subject = lines[0].trim();
        const body    = lines.slice(1).join('\n').trim();
        const { type } = parseSubject(subject);
        const key = TYPES[type] ? type : OTHER_KEY;
        if (!groups[key]) groups[key] = [];
        groups[key].push({ subject, body });
    }

    const sortedKeys = Object.keys(groups).sort((a, b) =>
        (TYPES[a]?.order ?? 99) - (TYPES[b]?.order ?? 99)
    );

    const compareUrl = prevReleaseTag
        ? `${GITHUB_REPO}/compare/${prevReleaseTag}...${tagName}`
        : `${GITHUB_REPO}/releases/tag/${tagName}`;

    let md = `## ${PROJECT_NAME} ${tagName}\n\n`;

    for (const key of sortedKeys) {
        const label = TYPES[key] ? TYPES[key].label : OTHER_LABEL;
        md += `### ${label}\n\n`;
        for (const { subject, body } of groups[key]) {
            md += `- ${formatBullet(subject)}\n`;
            if (body) {
                md += '\n';
                body.split('\n').forEach(l => { md += `  ${l.trimEnd()}\n`; });
                md += '\n';
            }
        }
        md += '\n';
    }

    md += `---\n\n**Full Changelog**: ${compareUrl}\n`;
    return md;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
    const version = readProjectVersion();
    const tagName = `v${version}`;

    console.log('\n──────────────────────────────────');
    console.log(` ${PROJECT_NAME} Release Script`);
    console.log('──────────────────────────────────');
    console.log(`Version : ${version}  →  tag: ${tagName}`);

    // 1. Clean working tree
    const dirty = run('git status --porcelain');
    if (dirty) abort(null, 'Working tree is not clean. Commit your changes first.\n\n' + dirty);

    // 2. Current branch
    const branch = run('git branch --show-current');
    if (branch !== 'main') {
        console.warn(`\n⚠   You are on branch "${branch}", not "main".`);
    }

    // 3. Tag existence check — skip creation if already present
    const tagExists = tryRun(`git rev-parse ${tagName}`).ok;
    if (tagExists) {
        console.warn(`\n⚠   Tag ${tagName} already exists — skipping tag creation.`);
    }

    // 4. gh CLI availability
    const ghAvail = tryRun('gh --version').ok;
    if (!ghAvail) {
        console.warn('\n⚠   GitHub CLI (gh) not found — the GitHub Release step will be skipped.');
        console.warn('    Install from https://cli.github.com/ to enable automatic release creation.\n');
    }

    // 5. Determine commit range from the previous GitHub release
    //    gh release list is the source of truth — fall back to git describe only when gh is unavailable.
    let prevReleaseTag = null;
    if (ghAvail) {
        const relListRes = tryRun(`gh release list --limit 10 --json tagName`);
        if (relListRes.ok) {
            try {
                const releases = JSON.parse(relListRes.out);
                const prev = releases.find(r => r.tagName !== tagName);
                if (prev) prevReleaseTag = prev.tagName;
            } catch (e) {}
        }
    }
    if (!prevReleaseTag) {
        const tipRef = tagExists ? `${tagName}~1` : 'HEAD';
        const prevTagRes = tryRun(`git describe --tags --abbrev=0 ${tipRef}`);
        if (prevTagRes.ok) prevReleaseTag = prevTagRes.out;
    }

    const rangeEnd    = tagExists ? tagName : 'HEAD';
    const commitRange = prevReleaseTag ? `${prevReleaseTag}..${rangeEnd}` : rangeEnd;

    const SEP = '__OPREADY_COMMIT__';
    const logRes = tryRun(`git log ${commitRange} --format=${SEP}%n%B`);
    const commits = logRes.ok
        ? logRes.out.split(SEP + '\n').map(s => s.trim()).filter(Boolean)
        : [];

    const sinceLabel = prevReleaseTag ? `since ${prevReleaseTag}` : 'all commits';
    console.log(`\nCommits in this release — ${sinceLabel} (${commits.length}):`);
    console.log('─'.repeat(50));
    if (commits.length === 0) {
        console.log('  (none)');
    } else {
        commits.forEach((msg, i) => {
            const lines = msg.split('\n');
            const subject = lines[0].trim();
            const body = lines.slice(1).join('\n').trim();
            console.log(`  ${i + 1}. ${subject}`);
            if (body) {
                body.split('\n').forEach(l => console.log(`     ${l}`));
                console.log('');
            }
        });
    }
    console.log('─'.repeat(50));

    // Pre-build structured markdown notes for step 10 (GitHub release)
    const autoNotes = buildMarkdownNotes(commits, tagName, prevReleaseTag);

    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

    // 6. Confirm
    console.log('');
    const confirm = (await ask(rl, `Release ${tagName}? (y/N): `)).trim().toLowerCase();
    if (confirm !== 'y') {
        console.log('Aborted.');
        rl.close();
        process.exit(0);
    }

    // 7. Optional custom release notes
    let customNotes = '';
    if (ghAvail) {
        console.log('\nRelease notes (press Enter to include all commit messages in full):');
        customNotes = (await ask(rl, '> ')).trim();
    }

    rl.close();

    // 8. Create tag (skip if it already existed)
    if (!tagExists) {
        console.log(`\nCreating tag ${tagName} ...`);
        run(`git tag ${tagName}`);
    }

    // 9. Push tag
    console.log('Pushing tag to origin ...');
    const pushResult = tryRun(`git push origin ${tagName}`);
    if (!pushResult.ok) {
        if (tagExists) {
            console.warn(`\n⚠   Could not push tag ${tagName} (it may already be on remote): ${pushResult.err}`);
        } else {
            run(`git tag -d ${tagName}`);
            abort(null, `git push failed — local tag removed.\n${pushResult.err}`);
        }
    }

    // 10. GitHub release
    if (ghAvail) {
        console.log('Creating GitHub release ...');

        if (tryRun(`gh release view ${tagName}`).ok) {
            console.warn(`\n⚠   GitHub release for ${tagName} already exists — nothing to do.`);
            console.log('\nDone.\n');
            return;
        }

        const notes = customNotes || autoNotes;

        const tmpFile = path.join(ROOT, '.release-notes.tmp');
        fs.writeFileSync(tmpFile, notes || '(no release notes)', 'utf8');
        const ghCmd = `gh release create ${tagName} --title "${tagName}" --notes-file "${tmpFile}"`;

        const ghResult = tryRun(ghCmd);
        if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile);

        if (!ghResult.ok) {
            console.warn(`\n⚠   GitHub release creation failed: ${ghResult.err}`);
            console.warn(`    Create it manually at: ${GITHUB_REPO}/releases/new?tag=${tagName}`);
        } else {
            console.log(`\n✔  Release published: ${GITHUB_REPO}/releases/tag/${tagName}`);
        }
    } else {
        console.log(`\n✔  Tag ${tagName} pushed.`);
        console.log(`   Create the GitHub Release at:`);
        console.log(`   ${GITHUB_REPO}/releases/new?tag=${tagName}`);
    }

    console.log('\nDone.\n');
}

main().catch(err => {
    console.error('\n✖  Unexpected error:', err.message);
    process.exit(1);
});
