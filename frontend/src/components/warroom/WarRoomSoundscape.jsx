import React, { useEffect, useRef } from 'react'
import { useWarRoom } from '../../context/WarRoomContext'
import { useWarRoomSound } from '../../hooks/useWarRoomSound'

export default function WarRoomSoundscape() {
  const { redTeamActive, lastFinding } = useWarRoom()
  const { playBlip, startAlarmHum, stopAlarmHum } = useWarRoomSound()
  const prevFindingIdRef = useRef(null)
  const humActiveRef = useRef(false)

  useEffect(() => {
    if (lastFinding && lastFinding.finding_id !== prevFindingIdRef.current) {
      prevFindingIdRef.current = lastFinding.finding_id
      playBlip()
    }
    if (!lastFinding) prevFindingIdRef.current = null
  }, [lastFinding, playBlip])

  useEffect(() => {
    if (redTeamActive && !humActiveRef.current) {
      humActiveRef.current = true
      startAlarmHum()
    } else if (!redTeamActive && humActiveRef.current) {
      humActiveRef.current = false
      stopAlarmHum()
    }
  }, [redTeamActive, startAlarmHum, stopAlarmHum])

  return null
}
