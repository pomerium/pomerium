//go:build darwin

package ipc

// not defined anywhere in any std / sys packages in go for darwin for some reason.
// https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/filio.h#L77
const FIONREAD = 0x4004667f
