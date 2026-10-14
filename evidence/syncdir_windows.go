//go:build windows

package evidence

// syncDir 在 Windows 上不做任何事。
//
// 这里刻意不调 os.File.Sync()：Windows 的 FlushFileBuffers 对**只读打开的目录句柄**
// 一律返回 ERROR_ACCESS_DENIED，所以「打开目录再 Sync」在 Windows 上必然报
// "sync <目录>: Access is denied."，会让证据正文的首次写入直接失败。
// 而 NTFS 的元数据日志本身保证了 rename 的目录项会持久化，这一步在 Windows 上
// 既做不到、也没有必要。
func syncDir(string) error {
	return nil
}
