/**
 * Shared page shell for domain-specific intelligence hubs.
 * Thin wrapper around AppShell — backward compatible props.
 */
import React from 'react'
import AppShell from '../components/layout/AppShell'

export default function PageShell({
  title,
  subtitle,
  badge,
  badgeColor = '#22d3ee',
  icon,
  actions,
  breadcrumbs,
  children,
  contentClassName,
  maxWidth,
}) {
  return (
    <AppShell
      title={title}
      subtitle={subtitle}
      badge={badge}
      badgeColor={badgeColor}
      icon={icon}
      actions={actions}
      breadcrumbs={breadcrumbs}
      contentClassName={contentClassName}
      maxWidth={maxWidth}
    >
      {children}
    </AppShell>
  )
}
