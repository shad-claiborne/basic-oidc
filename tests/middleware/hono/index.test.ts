import { describe, expect, test } from 'vitest';

describe("say what", () => {
    test('hello', () => {
        const input = Math.sqrt(4);
        expect(input).to.equal(2);
    });
});