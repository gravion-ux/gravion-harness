'use strict';

/**
 * Terminal chat.
 *
 * The operator drives the harness by typing commands, the same way they would
 * in the web UI. The chat is the same router, so anything that works in one
 * works in the other.
 */

const readline = require('node:readline');

const { createCommandRouter } = require('./commands');

/**
 * Runs the chat loop until the operator leaves.
 *
 * @param {object} harness
 * @param {{input?: object, output?: object, onQuit?: Function}} [options]
 * @returns {Promise<{router: object, lines: string[]}>}
 */
async function runChat(harness, options = {}) {
  const input = options.input || process.stdin;
  const output = options.output || process.stdout;
  const transcript = [];

  const router = createCommandRouter(harness, {
    onRunComplete: (result, error) => {
      if (error) {
        write(output, `The engagement failed: ${error}`);
        return;
      }
      const counts = result.report.summary.counts;
      write(output, [
        `Engagement finished. ${result.report.summary.total} finding(s).`,
        `critical ${counts.critical}, high ${counts.high}, medium ${counts.medium}, low ${counts.low}, info ${counts.info}`,
        'Type "report" to write the Markdown report.',
      ].join('\n'));
    },
  });

  const rl = readline.createInterface({ input, output, prompt: 'gravion> ' });

  write(output, 'Gravion Harness chat. Type "help" for the commands, "quit" to leave.');
  rl.prompt();

  const onLine = async (line) => {
    const text = String(line || '').trim();
    if (!text) {
      rl.prompt();
      return;
    }

    transcript.push(text);

    let result;
    try {
      result = await router.handle(text);
    } catch (error) {
      write(output, `Error: ${String(error && error.message ? error.message : error)}`);
      rl.prompt();
      return;
    }

    if (result && result.reply) {
      write(output, result.reply);
    }
    if (result && result.data && result.data.quit) {
      rl.close();
      return;
    }
    rl.prompt();
  };

  rl.on('line', onLine);

  await new Promise((resolve) => {
    rl.on('close', resolve);
  });

  if (typeof options.onQuit === 'function') {
    options.onQuit();
  }

  return { router, transcript };
}

/**
 * Writes a line to the output stream.
 *
 * @param {object} output
 * @param {string} text
 */
function write(output, text) {
  output.write(`${text}\n`);
}

module.exports = {
  runChat,
};
