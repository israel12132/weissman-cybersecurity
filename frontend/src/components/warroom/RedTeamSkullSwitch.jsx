import React from 'react'
import { motion } from 'framer-motion'
import { useClient } from '../../context/ClientContext'
import { useWarRoom } from '../../context/WarRoomContext'
import { Skull } from 'lucide-react'

export default function RedTeamSkullSwitch() {
  const { selectedClientId, clientConfig, patchConfig, configLoading } = useClient()
  const { redTeamActive, setRedTeamActive, confirmCommand, refuseCommand, commandRefused } = useWarRoom()
  const isWeaponized = (clientConfig?.roe_mode || 'safe_proofs') === 'weaponized_god_mode'

  React.useEffect(() => {
    setRedTeamActive(isWeaponized)
  }, [isWeaponized, setRedTeamActive])

  const handleToggle = async () => {
    if (configLoading || !selectedClientId) return
    const next = isWeaponized ? 'safe_proofs' : 'weaponized_god_mode'
    const ok = await patchConfig(selectedClientId, { roe_mode: next })
    if (ok && confirmCommand) confirmCommand('roe')
    else if (!ok && refuseCommand) refuseCommand()
  }

  return (
    <motion.div
      className="relative rounded-2xl bg-black/50 backdrop-blur-md border p-4 flex flex-col items-center gap-3"
      animate={{
        borderColor: commandRefused ? 'rgba(239, 68, 68, 0.9)' : isWeaponized ? 'rgba(239, 68, 68, 0.6)' : 'rgba(255,255,255,0.1)',
        boxShadow: commandRefused ? '0 0 20px rgba(239,68,68,0.6)' : isWeaponized ? '0 0 30px rgba(239,68,68,0.2)' : '0 0 0 transparent',
      }}
      transition={{ duration: 0.3 }}
    >
      {commandRefused && (
        <motion.span
          className="absolute -top-1 left-1/2 -translate-x-1/2 text-[10px] font-mono text-red-400 whitespace-nowrap"
          initial={{ opacity: 0, x: -4 }}
          animate={{ opacity: [1, 0.3, 1], x: [0, 2, -2, 0] }}
          transition={{ repeat: 2, duration: 0.15 }}
        >
          COMMAND REFUSED
        </motion.span>
      )}
      <span className="text-[10px] font-semibold text-white/50 uppercase tracking-[0.2em]">
        Weaponization
      </span>
      <button
        type="button"
        onClick={handleToggle}
        disabled={configLoading}
        className={`
          relative w-14 h-14 rounded-xl flex items-center justify-center
          transition-all duration-300 border-2
          disabled:opacity-50 disabled:cursor-not-allowed
          ${isWeaponized
            ? 'border-[#ef4444] bg-[#ef4444]/20 text-[#ef4444] shadow-[0_0_24px_rgba(239,68,68,0.5)]'
            : 'border-white/20 bg-white/5 text-white/60 hover:border-white/40 hover:text-white/80'
          }
        `}
        aria-label={isWeaponized ? 'Disable Red Team' : 'Enable Red Team'}
      >
        <Skull className="w-7 h-7" strokeWidth={2} />
      </button>
      <span className="text-[10px] text-white/60">
        {isWeaponized ? 'Red Team ON' : 'Proof only'}
      </span>
    </motion.div>
  )
}
