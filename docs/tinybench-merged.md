# tinybench - v5.0.1

---

# Class Bench

The Bench class keeps track of the benchmark tasks and controls them.

#### Hierarchy

- EventTargetBench
- Bench

---

# Class Task

A class that represents each benchmark task in Tinybench. It keeps track of the results, name, the task function, the number times the task function has been executed, ...

#### Hierarchy

- EventTargetTask
- Task

---

# Enumeration JSRuntime

The JavaScript runtime environment.

#### See

[https://runtime-keys.proposal.wintercg.org/](https://runtime-keys.proposal.wintercg.org/)

---

# Function hrtimeNow

```ts
function hrtimeNow(): number;
```

### Returns

number the current high resolution timestamp in milliseconds

---

# Function nToMs

```ts
function nToMs(ns: number): number;
```

### Parameters

- ns — number the nanoseconds to convert ####

### Returns

- number the milliseconds
- - ns: number the nanoseconds to convert

---

# tinybench - v5.0.1

## Hierarchy Summary

- [BenchOptions](interfaces/BenchOptions.html)[ResolvedBenchOptions](interfaces/ResolvedBenchOptions.html)
- [ResolvedBenchOptions](interfaces/ResolvedBenchOptions.html)

---

# Interface BenchEventsMap

```ts
interface BenchEventsMap {
  abort: [EventListener](../types/EventListener.html)
  add: [EventListener](../types/EventListener.html)
  complete: [EventListener](../types/EventListener.html)
  cycle: [EventListener](../types/EventListener.html)
  error: [EventListener](../types/EventListener.html)
  remove: [EventListener](../types/EventListener.html)
  reset: [EventListener](../types/EventListener.html)
  start: [EventListener](../types/EventListener.html)
  warmup: [EventListener](../types/EventListener.html)
}
```

---

# Interface BenchOptions

Bench options

```ts
interface BenchOptions {
  iterations?: number
  name?: string
  now?: () => number
  setup?: [Hook](../types/Hook.html)
  signal?: AbortSignal
  teardown?: [Hook](../types/Hook.html)
  throws?: boolean
  time?: number
  warmup?: boolean
  warmupIterations?: number
  warmupTime?: number
}
```

#### Hierarchy (View Summary)

- BenchOptions[ResolvedBenchOptions](ResolvedBenchOptions.html)
- [ResolvedBenchOptions](ResolvedBenchOptions.html)

---

# Interface FnOptions

The task function options

```ts
interface FnOptions {
  afterAll?: [FnHook](../types/FnHook.html)
  afterEach?: [FnHook](../types/FnHook.html)
  beforeAll?: [FnHook](../types/FnHook.html)
  beforeEach?: [FnHook](../types/FnHook.html)
}
```

---

# Interface FnReturnedObject

A possible object returned by task functions to override default behaviors, like the duration of the function itself.

```ts
interface FnReturnedObject {
  overriddenDuration?: number;
}
```

---

# Interface ResolvedBenchOptions

Bench options

```ts
interface ResolvedBenchOptions {
  iterations: number
  name?: string
  now: () => number
  setup: [Hook](../types/Hook.html)
  signal?: AbortSignal
  teardown: [Hook](../types/Hook.html)
  throws: NonNullable<undefined | boolean>
  time: number
  warmup: NonNullable<undefined | boolean>
  warmupIterations: number
  warmupTime: number
}
```

#### Hierarchy (View Summary)

- [BenchOptions](BenchOptions.html)ResolvedBenchOptions
- ResolvedBenchOptions

---

# Interface Statistics

The statistics object

```ts
interface Statistics {
  aad: undefined | number;
  critical: number;
  df: number;
  mad: undefined | number;
  max: number;
  mean: number;
  min: number;
  moe: number;
  p50: undefined | number;
  p75: undefined | number;
  p99: undefined | number;
  p995: undefined | number;
  p999: undefined | number;
  rme: number;
  samples: number[];
  sd: number;
  sem: number;
  variance: number;
}
```

---

# Interface TaskEventsMap

```ts
interface TaskEventsMap {
  abort: [EventListener](../types/EventListener.html)
  complete: [EventListener](../types/EventListener.html)
  cycle: [EventListener](../types/EventListener.html)
  error: [EventListener](../types/EventListener.html)
  reset: [EventListener](../types/EventListener.html)
  start: [EventListener](../types/EventListener.html)
  warmup: [EventListener](../types/EventListener.html)
}
```

---

# Interface TaskResult

The task result object

```ts
interface TaskResult {
  aborted: boolean
  critical: number
  df: number
  error?: Error
  hz: number
  latency: [Statistics](Statistics.html)
  max: number
  mean: number
  min: number
  moe: number
  p75: number
  p99: number
  p995: number
  p999: number
  period: number
  rme: number
  runtime: [JSRuntime](../enums/JSRuntime.html) | "unknown"
  runtimeVersion: string
  samples: number[]
  sd: number
  sem: number
  throughput: [Statistics](Statistics.html)
  totalTime: number
  variance: number
}
```

---

# Type Alias BenchEvent

BenchEvent: Event & { error?: Error; task?: [Task](../classes/Task.html) }
Bench event

---

# Type Alias BenchEvents

BenchEvents: | "abort" | "add" | "complete" | "cycle" | "error" | "remove" | "reset" | "start" | "warmup"
Bench events

---

# Type Alias EventListener

EventListener: (evt: [BenchEvent](BenchEvent.html)) => void
Event listener

#### Type declaration

- (evt: [BenchEvent](BenchEvent.html)): void ####

### Parameters

- evt — [BenchEvent](BenchEvent.html) ####

### Returns

- void
- - (evt: [BenchEvent](BenchEvent.html)): void
- - ####

### Parameters

- evt — [BenchEvent](BenchEvent.html) ####

### Returns

- void
- - evt: [BenchEvent](BenchEvent.html)

---

# Type Alias Fn

Fn: () => [FnReturnedObject](../interfaces/FnReturnedObject.html) | Promise<[FnReturnedObject](../interfaces/FnReturnedObject.html) | unknown> | unknown
The task function.

If you need to provide a custom duration for the task (e.g.: because you want to measure a specific part of its execution), you can return an object with a overriddenDuration field. You should still use bench.opts.now() to measure that duration.

#### Type declaration

- (): [FnReturnedObject](../interfaces/FnReturnedObject.html) | Promise<[FnReturnedObject](../interfaces/FnReturnedObject.html) | unknown> | unknown ####

### Returns

- FnReturnedObject | Promise<FnReturnedObject | unknown> | unknown
- - (): [FnReturnedObject](../interfaces/FnReturnedObject.html) | Promise<[FnReturnedObject](../interfaces/FnReturnedObject.html) | unknown> | unknown
- - ####

### Returns

FnReturnedObject | Promise<FnReturnedObject | unknown> | unknown

---

# Type Alias FnHook

FnHook: (this: [Task](../classes/Task.html), mode?: "run" | "warmup") => Promise<void> | void
The task hook function signature. If warmup is enabled, the hook will be called twice, once for the warmup and once for the run.

#### Type declaration

- (this: [Task](../classes/Task.html), mode?: "run" | "warmup"): Promise<void> | void ####

### Parameters

- this — [Task](../classes/Task.html)Optional mode: "run" | "warmup" the mode where the hook is being called ####

### Returns

- Promise<void> | void
- - (this: [Task](../classes/Task.html), mode?: "run" | "warmup"): Promise<void> | void
- - ####

### Parameters

- this — [Task](../classes/Task.html)Optional mode: "run" | "warmup" the mode where the hook is being called ####

### Returns

- Promise<void> | void
- - this: [Task](../classes/Task.html)
- - Optional mode: "run" | "warmup" the mode where the hook is being called

---

# Type Alias Hook

Hook: (task?: [Task](../classes/Task.html), mode?: "run" | "warmup") => Promise<void> | void
The hook function signature. If warmup is enabled, the hook will be called twice, once for the warmup and once for the run.

#### Type declaration

- (task?: [Task](../classes/Task.html), mode?: "run" | "warmup"): Promise<void> | void ####

### Parameters

- Optional — task: [Task](../classes/Task.html) the task instance Optional mode: "run" | "warmup" the mode where the hook is being called ####

### Returns

- Promise<void> | void
- - (task?: [Task](../classes/Task.html), mode?: "run" | "warmup"): Promise<void> | void
- - ####

### Parameters

- Optional — task: [Task](../classes/Task.html) the task instance Optional mode: "run" | "warmup" the mode where the hook is being called ####

### Returns

- Promise<void> | void
- - Optional task: [Task](../classes/Task.html) the task instance
- - Optional mode: "run" | "warmup" the mode where the hook is being called

---

# Type Alias TaskEvents

TaskEvents: | "abort" | "complete" | "cycle" | "error" | "reset" | "start" | "warmup"
Task events

---

# Variable nowConst

- now
  now: () => number = performanceNow

#### Type declaration

- (): number

### Returns

- the current high resolution millisecond timestamp, where 0 represents the start of the current node process. #### Returns number #### Since v8.5.0
- - (): number
- -

### Returns

the current high resolution millisecond timestamp, where 0 represents the start of the current node process. #### Returns number #### Since v8.5.0

---
