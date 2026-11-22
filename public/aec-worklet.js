/**
 * aec-worklet.js — 真正可用的软件级回声消除（AEC）
 *
 * 算法：NLMS（归一化最小均方）自适应滤波器
 * 输入0：近端麦克风信号（混杂了扬声器里对方的声音 = 回声）
 * 输入1：远端参考信号（对方的声音，还没进扬声器）
 * 输出：近端信号减去估计的回声 = 干净的本机人声
 *
 * 运行在音频渲染线程，低延迟，不会阻塞主线程。
 */

class AECProcessor extends AudioWorkletProcessor {
    constructor(options) {
        super();
        // 滤波器长度（样本数）。16kHz 采样下 1024 样本约 64ms，覆盖常见回声延迟
        this.filterLength = (options && options.processorOptions && options.processorOptions.filterLength) || 1024;
        this.w = new Float32Array(this.filterLength);      // 自适应滤波器系数
        this.xBuf = new Float32Array(this.filterLength);   // 参考信号延迟线
        this.xIndex = 0;

        this.enabled = true;
        this.suppression = 0.35;   // 残留回声抑制增益（0-1，越小抑制越强）
        this.mu = 0.25;            // NLMS 步长（0-1，越大收敛越快但可能不稳）
        this.epsilon = 1e-6;       // 防止除零

        // 远端参考信号能量（用于门控：对方没说话时不更新滤波器，防止误收敛）
        this.refEnergy = 0;
        this.refActive = false;
        this.smoothRef = 0;

        this.port.onmessage = (e) => {
            const d = e.data;
            if (d.type === 'enabled') this.enabled = !!d.value;
            if (d.type === 'suppression') this.suppression = Math.max(0.05, Math.min(1, d.value));
            if (d.type === 'reset') {
                this.w.fill(0);
                this.xBuf.fill(0);
                this.xIndex = 0;
            }
        };
    }

    process(inputs, outputs) {
        const mic = inputs[0] && inputs[0][0];       // 近端麦克风
        const ref = inputs[1] && inputs[1][0];       // 远端参考
        const out = outputs[0] && outputs[0][0];
        if (!mic || !out) return true;

        const n = mic.length;

        if (!this.enabled || !ref) {
            // 未启用或没有参考信号：直接透传
            out.set(mic);
            return true;
        }

        for (let i = 0; i < n; i++) {
            const d = mic[i];
            const r = ref[i] || 0;

            // 更新参考信号延迟线（环形缓冲）
            this.xBuf[this.xIndex] = r;

            // 计算远端参考能量（平滑）
            this.smoothRef = this.smoothRef * 0.98 + (r * r) * 0.02;
            this.refActive = this.smoothRef > 1e-7;

            // 计算估计回声 y = w · x（点积，遍历延迟线）
            let echo = 0;
            let idx = this.xIndex;
            for (let k = 0; k < this.filterLength; k++) {
                echo += this.w[k] * this.xBuf[idx];
                idx--;
                if (idx < 0) idx = this.filterLength - 1;
            }

            // 残差 = 麦克风 - 估计回声
            let e = d - echo;

            // NLMS 权重更新：仅在远端有声时更新（防止对方静音时误收敛）
            if (this.refActive) {
                let power = 0;
                idx = this.xIndex;
                for (let k = 0; k < this.filterLength; k++) {
                    const xv = this.xBuf[idx];
                    power += xv * xv;
                    idx--;
                    if (idx < 0) idx = this.filterLength - 1;
                }
                const norm = this.mu / (power + this.epsilon);
                idx = this.xIndex;
                for (let k = 0; k < this.filterLength; k++) {
                    this.w[k] += norm * e * this.xBuf[idx];
                    idx--;
                    if (idx < 0) idx = this.filterLength - 1;
                }
            }

            // 残留回声抑制：对方说话时，对残差做额外衰减
            out[i] = this.refActive ? e * this.suppression + d * (1 - this.suppression) * 0.15 : e;

            this.xIndex++;
            if (this.xIndex >= this.filterLength) this.xIndex = 0;
        }

        return true;
    }
}

registerProcessor('aec-processor', AECProcessor);
