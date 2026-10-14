//go:build !windows

package evidence

import "os"

// syncDir 把目录项本身刷到盘上。rename 之后必须做这一步，否则崩溃时可能出现
// 「文件内容已落盘、目录里却还看不到这个文件名」的状态。
//
// POSIX 下对目录 fd 调 fsync 是标准做法。
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
