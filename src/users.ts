export type User = {
  username: string
  name: string
  age: number
  social: string
  password: string
}

export const users: User[] = [
  {
    name: 'Lucas Santos',
    age: 27,
    social: 'twitter.lsantos.dev',
    username: 'lsantosdev',
    password: '123456'
  },
  {
    name: 'Rosa Barnett',
    age: 33,
    social: 'http://ko.st/wa',
    username: 'rosabarnett',
    password: '123456'
  },
  {
    name: 'Russell Spencer',
    age: 66,
    social: 'http://egki.tp/ecbu',
    username: 'russellspencer',
    password: '123456'
  }
]
