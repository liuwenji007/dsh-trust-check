/** @vitest-environment jsdom */
import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { ExplainMarkdown } from '../../src/client/explain-markdown.tsx'

afterEach(() => {
  cleanup()
})

describe('ExplainMarkdown', () => {
  it('renders mixed titles, lists, bold, and code without raw markers', () => {
    render(
      <ExplainMarkdown
        text={[
          '**dshmarket@1.66.14 案例分析**',
          '**用途推断**',
          '- 从依赖看它注入 `dsh-client-locale/ui-settings`',
          '- 同步网盘 `dav.jianguoyun.com`',
          '**主要需谨慎的点**',
          '- 读取 git 配置：`spawnSync(\'git\', [\'config\'])` @ `lib/dsh-cli.js:185`',
          '普通段落里也有 **加粗**。',
        ].join('\n')}
      />,
    )

    expect(screen.getByText('dshmarket@1.66.14 案例分析').className).toContain('explainTitle')
    expect(screen.getByText('用途推断').className).toContain('explainTitle')
    expect(screen.getByText('主要需谨慎的点').className).toContain('explainTitle')
    expect(screen.getByText('dav.jianguoyun.com').tagName).toBe('CODE')
    expect(screen.getByText('lib/dsh-cli.js:185').tagName).toBe('CODE')
    expect(screen.getByText('加粗').tagName).toBe('STRONG')
    expect(screen.getAllByRole('list')).toHaveLength(2)
    expect(screen.getAllByRole('listitem')).toHaveLength(3)
    expect(document.body.textContent).not.toContain('**')
    expect(document.body.textContent).not.toContain('`dav.jianguoyun.com`')
  })

  it('keeps plain text readable when there is no markdown', () => {
    render(<ExplainMarkdown text={'第一行\n第二行'} />)
    expect(screen.getByText(/第一行/)).toBeTruthy()
    expect(screen.getByText(/第二行/)).toBeTruthy()
  })
})
