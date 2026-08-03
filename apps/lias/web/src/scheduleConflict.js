// Schedule Conflict Detection & Minute-Grid Projection Engine
//
// File:    apps/lias/web/src/scheduleConflict.js
// Version: 1.1 (Added expandDayRange & parseTime exports)

const DAY_MAP = {
  sun: 0, sunday: 0,
  mon: 1, monday: 1,
  tue: 2, tuesday: 2,
  wed: 3, wednesday: 3,
  thu: 4, thursday: 4,
  fri: 5, friday: 5,
  sat: 6, saturday: 6
};

const DAY_NAMES = ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"];

export function parseTime(timeStr) {
  if (!timeStr) return 0;
  const parts = timeStr.split(':');
  return parseInt(parts[0], 10) * 60 + parseInt(parts[1], 10);
}

export function formatMinuteOfWeek(m) {
  m = ((m % 10080) + 10080) % 10080;
  const dayIdx = Math.floor(m / 1440);
  const minOfDay = m % 1440;
  const hh = String(Math.floor(minOfDay / 60)).padStart(2, '0');
  const mm = String(minOfDay % 60).padStart(2, '0');
  return { day: DAY_NAMES[dayIdx], time: `${hh}:${mm}` };
}

export function expandDayRange(fromDay, toDay) {
  const daysOrder = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'];
  const startIdx = daysOrder.indexOf(fromDay.toLowerCase().substring(0, 3));
  const endIdx = daysOrder.indexOf(toDay.toLowerCase().substring(0, 3));

  if (startIdx === -1 || endIdx === -1) return [fromDay];

  const result = [];
  let curr = startIdx;
  while (true) {
    result.push(daysOrder[curr]);
    if (curr === endIdx) break;
    curr = (curr + 1) % 7;
  }
  return result;
}

export function projectSchedule(schedule) {
  const segments = [];
  if (!schedule || !schedule.rules) return segments;

  schedule.rules.forEach((rule, ruleIdx) => {
    const startMin = parseTime(rule.start_time);
    const endMin = parseTime(rule.end_time);

    if (startMin === endMin) return;

    (rule.days || []).forEach(dStr => {
      const dLower = String(dStr).toLowerCase().trim();
      const dayIdx = DAY_MAP[dLower];
      if (dayIdx === undefined) return;

      if (startMin < endMin) {
        segments.push({
          start: dayIdx * 1440 + startMin,
          end: dayIdx * 1440 + endMin,
          action: rule.action,
          scheduleId: schedule.id,
          scheduleName: schedule.name,
          sourceRuleIdx: ruleIdx
        });
      } else {
        // Overnight window (e.g. 22:00 -> 06:00)
        // Segment 1: startMin to midnight on current day
        segments.push({
          start: dayIdx * 1440 + startMin,
          end: (dayIdx + 1) * 1440,
          action: rule.action,
          scheduleId: schedule.id,
          scheduleName: schedule.name,
          sourceRuleIdx: ruleIdx
        });

        // Segment 2: midnight to endMin on next day
        const nextDayIdx = (dayIdx + 1) % 7;
        segments.push({
          start: nextDayIdx * 1440,
          end: nextDayIdx * 1440 + endMin,
          action: rule.action,
          scheduleId: schedule.id,
          scheduleName: schedule.name,
          sourceRuleIdx: ruleIdx
        });
      }
    });
  });

  return segments;
}

export function detectConflicts(schedules) {
  if (!schedules || schedules.length === 0) return [];

  const allSegments = [];
  schedules.forEach(s => {
    allSegments.push(...projectSchedule(s));
  });

  allSegments.sort((a, b) => a.start - b.start || a.end - b.end);

  const conflicts = [];
  const seen = new Set();

  for (let i = 0; i < allSegments.length; i++) {
    for (let j = i + 1; j < allSegments.length; j++) {
      if (allSegments[j].start >= allSegments[i].end) break;

      const overlapStart = Math.max(allSegments[i].start, allSegments[j].start);
      const overlapEnd = Math.min(allSegments[i].end, allSegments[j].end);

      if (overlapStart < overlapEnd) {
        if (allSegments[i].action !== allSegments[j].action) {
          if (allSegments[i].scheduleId !== allSegments[j].scheduleId || allSegments[i].sourceRuleIdx !== allSegments[j].sourceRuleIdx) {
            const startFmt = formatMinuteOfWeek(overlapStart);
            const endFmt = formatMinuteOfWeek(overlapEnd);

            const key = `${allSegments[i].scheduleId}|${allSegments[j].scheduleId}|${startFmt.day}|${startFmt.time}|${endFmt.time}`;
            if (!seen.has(key)) {
              seen.add(key);
              conflicts.push({
                schedule_a_id: allSegments[i].scheduleId,
                schedule_a_name: allSegments[i].scheduleName,
                schedule_b_id: allSegments[j].scheduleId,
                schedule_b_name: allSegments[j].scheduleName,
                day: startFmt.day,
                overlap_start: startFmt.time,
                overlap_end: endFmt.time,
                action_a: allSegments[i].action,
                action_b: allSegments[j].action
              });
            }
          }
        }
      }
    }
  }

  return conflicts;
}
